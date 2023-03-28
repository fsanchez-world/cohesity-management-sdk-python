# -*- coding: utf-8 -*-
# Copyright 2023 Cohesity Inc.

class TargetHostTypeEnum(object):

    """Implementation of the 'TargetHostType' enum.
    Specifies the target host types to be restored. 'kLinux' indicates the
    Linux operating system. 'kWindows' indicates the Microsoft Windows
    operating system. 'kAix' indicates the IBM AIX operating system. 'kSolaris'
    indicates the Oracle Solaris operating system. 'kSapHana' indicates the Sap
    Hana database system developed by SAP SE. 'kSapOracle' indicates the Sap
    Oracle database system developed by SAP SE. 'kCockroachDB' indicates the
    CockroachDB database system. 'kMySQL' indicates the MySQL database system.
    'kOther' indicates the other types of operating system.


    Attributes:
        KLINUX: TODO: type description here.
        KWINDOWS: TODO: type description here.
        KAIX: TODO: type description here.
        KSOLARIS: TODO: type description here.
        KSAPHANA: TODO: type description here.
        KSAPORACLE: TODO: type description here.
        KCOCKROACHDB: TODO: type description here.
        KMYSQL: TODO: type description here.
        KOTHER: TODO: type description here.

    """

    KLINUX = 'kLinux'

    KWINDOWS = 'kWindows'

    KAIX = 'kAix'

    KSOLARIS = 'kSolaris'

    KSAPHANA = 'kSapHana'

    KSAPORACLE = 'kSapOracle'

    KCOCKROACHDB = 'kCockroachDB'

    KMYSQL = 'kMySQL'

    KOTHER = 'kOther'
