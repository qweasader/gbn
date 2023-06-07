# OpenVAS Vulnerability Test
#
# Security update for PHP4
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.65172");
  script_version("2022-01-24T09:41:29+0000");
  script_tag(name:"last_modification", value:"2022-01-24 09:41:29 +0000 (Mon, 24 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-10-10 16:11:46 +0200 (Sat, 10 Oct 2009)");
  script_cve_id("CVE-2007-1285", "CVE-2007-3007", "CVE-2007-2756", "CVE-2007-2872", "CVE-2007-1396", "CVE-2007-1864", "CVE-2007-2509");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
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

    php4-bcmath
    php4-sysvshm
    php4-gmp
    php4-pgsql
    php4-xslt
    php4-curl
    mod_php4-servlet
    php4-ftp
    php4-sockets
    php4-dbase
    php4
    php4-mbstring
    php4-sysvsem
    php4-shmop
    php4-domxml
    php4-iconv
    mod_php4-core
    php4-swf
    mod_php4
    php4-ldap
    php4-yp
    php4-unixODBC
    php4-wddx
    php4-ctype
    php4-recode
    php4-mysql
    php4-gettext
    php4-dba
    php4-gd
    php4-servlet
    php4-devel
    php4-qtdom
    php4-fastcgi
    php4-imap
    php4-exif
    php4-calendar
    apache-mod_php4
    php4-mcrypt
    php4-zlib
    mod_php4-apache2
    php4-filepro
    php4-mhash
    php4-mcal
    php4-session
    php4-readline
    php4-bz2
    php4-pear
    php4-mime_magic
    php4-snmp
    apache2-mod_php4

For more information, please visit the referenced security
advisories.

More details may also be found by searching for keyword
5012110 within the SuSE Enterprise Server 9 patch
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
if ((res = isrpmvuln(pkg:"php4-bcmath", rpm:"php4-bcmath~4.3.4~43.79", rls:"SLES9.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
