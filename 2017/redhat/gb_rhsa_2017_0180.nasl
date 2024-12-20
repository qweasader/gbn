# Copyright (C) 2017 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871749");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2017-01-21 05:41:52 +0100 (Sat, 21 Jan 2017)");
  script_cve_id("CVE-2016-5546", "CVE-2016-5547", "CVE-2016-5548", "CVE-2016-5552",
                "CVE-2017-3231", "CVE-2017-3241", "CVE-2017-3252", "CVE-2017-3253",
                "CVE-2017-3261", "CVE-2017-3272", "CVE-2017-3289", "CVE-2016-2183");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for java-1.8.0-openjdk RHSA-2017:0180-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.8.0-openjdk'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The java-1.8.0-openjdk packages provide the
OpenJDK 8 Java Runtime Environment and the OpenJDK 8 Java Software Development Kit.

Security Fix(es):

  * It was discovered that the RMI registry and DCG implementations in the
RMI component of OpenJDK performed deserialization of untrusted inputs. A
remote attacker could possibly use this flaw to execute arbitrary code with
the privileges of RMI registry or a Java RMI application. (CVE-2017-3241)

This issue was addressed by introducing whitelists of classes that can be
deserialized by RMI registry or DCG. These whitelists can be customized
using the newly introduced sun.rmi.registry.registryFilter and
sun.rmi.transport.dgcFilter security properties.

  * Multiple flaws were discovered in the Libraries and Hotspot components in
OpenJDK. An untrusted Java application or applet could use these flaws to
completely bypass Java sandbox restrictions. (CVE-2017-3272, CVE-2017-3289)

  * A covert timing channel flaw was found in the DSA implementation in the
Libraries component of OpenJDK. A remote attacker could possibly use this
flaw to extract certain information about the used key via a timing side
channel. (CVE-2016-5548)

  * It was discovered that the Libraries component of OpenJDK accepted ECSDA
signatures using non-canonical DER encoding. This could cause a Java
application to accept signature in an incorrect format not accepted by
other cryptographic tools. (CVE-2016-5546)

  * It was discovered that the 2D component of OpenJDK performed parsing of
iTXt and zTXt PNG image chunks even when configured to ignore metadata. An
attacker able to make a Java application parse a specially crafted PNG
image could cause the application to consume an excessive amount of memory.
(CVE-2017-3253)

  * It was discovered that the Libraries component of OpenJDK did not
validate the length of the object identifier read from the DER input before
allocating memory to store the OID. An attacker able to make a Java
application decode a specially crafted DER input could cause the
application to consume an excessive amount of memory. (CVE-2016-5547)

  * It was discovered that the JAAS component of OpenJDK did not use the
correct way to extract user DN from the result of the user search LDAP
query. A specially crafted user LDAP entry could cause the application to
use an incorrect DN. (CVE-2017-3252)

  * It was discovered that the Networking component of OpenJDK failed to
properly parse user info from the URL. A remote ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"java-1.8.0-openjdk on
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2017:0180-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-January/msg00039.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(7|6)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.121~0.b13.el7_3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-debuginfo", rpm:"java-1.8.0-openjdk-debuginfo~1.8.0.121~0.b13.el7_3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.121~0.b13.el7_3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.121~0.b13.el7_3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.121~0.b13.el6_8", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-debuginfo", rpm:"java-1.8.0-openjdk-debuginfo~1.8.0.121~0.b13.el6_8", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.121~0.b13.el6_8", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.121~0.b13.el6_8", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
