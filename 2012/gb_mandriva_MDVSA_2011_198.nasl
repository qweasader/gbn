###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for phpmyadmin MDVSA-2011:198 (phpmyadmin)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2012-01/msg00000.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831522");
  script_version("2022-05-31T15:35:19+0100");
  script_tag(name:"last_modification", value:"2022-05-31 15:35:19 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2012-01-09 13:30:32 +0530 (Mon, 09 Jan 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_xref(name:"MDVSA", value:"2011:198");
  script_cve_id("CVE-2011-4107", "CVE-2011-4634", "CVE-2011-4782", "CVE-2011-4780");
  script_name("Mandriva Update for phpmyadmin MDVSA-2011:198 (phpmyadmin)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpmyadmin'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_mes5");
  script_tag(name:"affected", value:"phpmyadmin on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in phpmyadmin:

  Importing a specially-crafted XML file which contains an XML entity
  injection permits to retrieve a local file (limited by the privileges
  of the user running the web server) (CVE-2011-4107).

  Using crafted database names, it was possible to produce XSS in the
  Database Synchronize and Database rename panels. Using an invalid
  and crafted SQL query, it was possible to produce XSS when editing
  a query on a table overview panel or when using the view creation
  dialog. Using a crafted column type, it was possible to produce XSS
  in the table search and create index dialogs (CVE-2011-4634).

  Crafted values entered in the setup interface can produce XSS. Also,
  if the config directory exists and is writeable, the XSS payload can
  be saved to this directory (CVE-2011-4782).

  Using crafted url parameters, it was possible to produce XSS
  on the export panels in the server, database and table sections
  (CVE-2011-4780).

  This upgrade provides the latest phpmyadmin version (3.4.9) to address
  these vulnerabilities.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"phpmyadmin", rpm:"phpmyadmin~3.4.9~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
