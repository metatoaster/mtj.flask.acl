import logging

from passlib.hash import sha256_crypt

import sqlalchemy
from sqlalchemy import Column, Integer, String, MetaData
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from mtj.flask.acl.base import BaseAcl
from mtj.flask.acl import flask

Base = declarative_base()

logger = logging.getLogger('mtj.flask.acl.sqlacl')


class User(Base):

    __tablename__ = 'user'

    login = Column(String(255), primary_key=True)
    password = Column(String(255))
    name = Column(String(255))
    email = Column(String(255))

    def __init__(self, login, password, name=None, email=None, *a, **kw):
        self.login = login
        self.name = name
        self.email = email
        self.setPassword(password)

    def setPassword(self, password):
        # TODO fix this probable bad practices
        assert isinstance(password, basestring)
        assert len(password) > 5
        self.password = sha256_crypt.encrypt(password)


class Group(Base):

    __tablename__ = 'group'

    name = Column(String(255), primary_key=True)
    description = Column(String(255))

    def __init__(self, name, description):
        self.name = name
        self.description = description


class UserGroup(Base):

    __tablename__ = 'user_group'

    id = Column(Integer, primary_key=True)
    user = Column(String(255), index=True)
    group = Column(String(255), index=True)

    def __init__(self, user, group):
        self.user = user
        self.group = group


class GroupRole(Base):

    __tablename__ = 'group_role'

    id = Column(Integer, primary_key=True)
    group = Column(String(255), index=True)
    role = Column(String(255), index=True)

    def __init__(self, group, role):
        self.group = group
        self.role = role


class SqlAcl(BaseAcl):
    """
    Low level SQLAlchemy basd ACL backend.
    """

    def __init__(self, src=None, *a, **kw):
        # XXX for the session/access token table.
        super(SqlAcl, self).__init__(*a, **kw)

        if not src:
            src = 'sqlite://'

        self._conn = create_engine(src)
        self._metadata = MetaData()
        self._metadata.reflect(bind=self._conn)
        Base.metadata.create_all(self._conn)
        # XXX scoped_session needed here
        self._sessions = sessionmaker(
            bind=self._conn,
        )

        # XXX also need to autoinsert hook from somewhere...

        self.src = src

        setup_login = kw.pop('setup_login', None)
        setup_password = kw.pop('setup_password', None)
        if setup_login and setup_password:
            self._registerAdmin(setup_login, setup_password)

    def _registerAdmin(self, setup_login, setup_password):
        result = self.register(login=setup_login, password=setup_password)
        if not result:
            return False

        user = self.getUser(setup_login)

        admin_grp = Group('admin', 'Adminstrator group')
        session = self.session()
        session.merge(admin_grp)
        session.commit()

        self.setUserGroups(user, ('admin',))

        roles = self.getGroupRoles(admin_grp)
        roles.add('admin')
        self.setGroupRoles(admin_grp, roles)

    def session(self):
        return self._sessions()

    def validate(self, login, password):
        user = self.getUser(login)
        if user is None:
            # Data leakage potential via timing attack.  Mitigation: 
            # generate a new crypt to emuluate the time spent on
            # crypting/comparing the result.
            # TODO verify timings as crypt.verify does a bit more than
            # this.
            try:
                sha256_crypt.encrypt(password)
            except:
                pass
            return False

        try:
            result = sha256_crypt.verify(password, user.password)
        except TypeError:
            # this can be caused if password is empty.
            return False

        return result

    def register(self, *a, **kw):
        try:
            u = User(*a, **kw)
        except:
            return False

        if self.getUser(u.login):
            return False

        session = self.session()
        session.add(u)
        session.commit()
        return True

    def listUsers(self):
        session = self.session()
        q = session.query(User)
        return q.all()

    def getUser(self, login):
        session = self.session()
        q = session.query(User).filter(User.login == login)
        session.close()
        return q.first()

    def getGroup(self, group_name):
        session = self.session()
        q = session.query(Group).filter(Group.name == group_name)
        session.close()
        return q.first()

    def addGroup(self, name, description=None):
        g = Group(name, description)
        session = self.session()
        session.add(g)
        session.commit()

    def listGroups(self):
        session = self.session()
        q = session.query(Group)
        return q.all()

    def setUserGroups(self, user, groups):
        all_groups = {g.name for g in self.listGroups()}
        session = self.session()
        session.query(UserGroup).filter(UserGroup.user == user.login).delete()
        for group in set(groups):
            if group not in all_groups:
                continue
            session.add(UserGroup(user.login, group))
        session.commit()

    def getUserGroups(self, user):
        session = self.session()
        q = session.query(Group).filter(Group.name.in_(
            session.query(UserGroup.group).filter(UserGroup.user == user.login)
        ))
        results = q.all()
        session.close()
        return results

    def editUser(self, login, name=None, email=None):
        user = self.getUser(login)
        if not user:
            return False

        user.name = name
        user.email = email

        session = self.session()
        session.merge(user)
        session.commit()
        return True

    def editGroup(self, group_name, description=None):
        group = self.getGroup(group_name)
        if not group:
            return False

        group.description = description

        session = self.session()
        session.merge(group)
        session.commit()
        return True

    def updatePassword(self, login, password):
        user = self.getUser(login)
        if not user:
            return False

        try:
            user.setPassword(password)
        except:
            return False

        session = self.session()
        session.merge(user)
        session.commit()
        return True

    # roles

    def setGroupRoles(self, group, roles):
        session = self.session()
        session.query(GroupRole).filter(
            GroupRole.group == group.name).delete()
        for role in set(roles):
            if role not in flask._roles:
                continue
            session.merge(GroupRole(group.name, role))
        session.commit()

    def getGroupRoles(self, group):
        session = self.session()
        q = session.query(GroupRole.role).filter(
            GroupRole.group == group.name)
        results = set(i[0] for i in q.all())
        session.close()
        return results

    def getUserRoles(self, user):
        session = self.session()
        q = session.query(GroupRole.role).join(Group,
            GroupRole.group == Group.name).filter(Group.name.in_(
                session.query(UserGroup.group).filter(
                    UserGroup.user == user.login)
                ))
        results = set(i[0] for i in q.all())
        session.close()
        return results
