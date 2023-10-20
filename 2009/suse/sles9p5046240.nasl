# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.65516");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-10 16:11:46 +0200 (Sat, 10 Oct 2009)");
  script_cve_id("CVE-2008-5557");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SLES9: Security update for PHP4");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=SLES9\.0");
  script_tag(name:"solution", value:"Please install the updates provided by SuSE.");
  script_tag(name:"summary", value:"The remote host is missing updates to packages that affect
the security of your system.  One or more of the following packages
are affected:

    apache-mod_php4
    apache2-mod_php4
    mod_php4
    mod_php4-apache2
    mod_php4-core
    mod_php4-servlet
    php4
    php4-bcmath
    php4-bz2
    php4-calendar
    php4-ctype
    php4-curl
    php4-dba
    php4-dbase
    php4-devel
    php4-domxml
    php4-exif
    php4-fastcgi
    php4-filepro
    php4-ftp
    php4-gd
    php4-gettext
    php4-gmp
    php4-iconv
    php4-imap
    php4-ldap
    php4-mbstring
    php4-mcal
    php4-mcrypt
    php4-mhash
    php4-mime_magic
    php4-mysql
    php4-pear
    php4-pgsql
    php4-qtdom
    php4-readline
    php4-recode
    php4-servlet
    php4-session
    php4-shmop
    php4-snmp
    php4-sockets
    php4-swf
    php4-sysvsem
    php4-sysvshm
    php4-unixODBC
    php4-wddx
    php4-xslt
    php4-yp
    php4-zlib

For more information, please visit the referenced security
advisories.

More details may also be found by searching for keyword
5046240 within the SuSE Enterprise Server 9 patch
database linked in the references.");

  script_xref(name:"URL", value:"http://download.novell.com/patch/finder/");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"apache-mod_php4", rpm:"apache-mod_php4~4.3.4~43.91", rls:"SLES9.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
