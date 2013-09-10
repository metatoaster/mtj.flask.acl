class AclError(Exception):
    """
    Generic ACL related exception.
    """

class SiteAclMissingError(AclError):
    """
    Site ACL is missing.
    """
