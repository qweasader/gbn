# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.1257.1");
  script_cve_id("CVE-2013-1500", "CVE-2013-1571", "CVE-2013-2400", "CVE-2013-2407", "CVE-2013-2412", "CVE-2013-2437", "CVE-2013-2442", "CVE-2013-2443", "CVE-2013-2444", "CVE-2013-2446", "CVE-2013-2447", "CVE-2013-2448", "CVE-2013-2449", "CVE-2013-2450", "CVE-2013-2451", "CVE-2013-2452", "CVE-2013-2453", "CVE-2013-2454", "CVE-2013-2455", "CVE-2013-2456", "CVE-2013-2457", "CVE-2013-2458", "CVE-2013-2459", "CVE-2013-2460", "CVE-2013-2462", "CVE-2013-2463", "CVE-2013-2464", "CVE-2013-2465", "CVE-2013-2466", "CVE-2013-2468", "CVE-2013-2469", "CVE-2013-2470", "CVE-2013-2471", "CVE-2013-2472", "CVE-2013-2473", "CVE-2013-3006", "CVE-2013-3007", "CVE-2013-3008", "CVE-2013-3009", "CVE-2013-3010", "CVE-2013-3011", "CVE-2013-3012", "CVE-2013-3743", "CVE-2013-3744", "CVE-2013-4002");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:24 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-08-09T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:1257-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:1257-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20131257-1/");
  script_xref(name:"URL", value:"http://www.ibm.com/developerworks/java/jdk/alerts/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_0-ibm' package(s) announced via the SUSE-SU-2013:1257-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"IBM Java 1.7.0 has been updated to SR5 to fix bugs and security issues.

Please see also [link moved to references]

Also the following bugs have been fixed:

 * add Europe/Busingen to tzmappings (bnc#817062)
 * mark files in jre/bin and bin/ as executable
(bnc#823034)

Security Issue references:

 * CVE-2013-3006
>
 * CVE-2013-3007
>
 * CVE-2013-3008
>
 * CVE-2013-3009
>
 * CVE-2013-3010
>
 * CVE-2013-3011
>
 * CVE-2013-3012
>
 * CVE-2013-4002
>
 * CVE-2013-2468
>
 * CVE-2013-2469
>
 * CVE-2013-2465
>
 * CVE-2013-2464
>
 * CVE-2013-2463
>
 * CVE-2013-2473
>
 * CVE-2013-2472
>
 * CVE-2013-2471
>
 * CVE-2013-2470
>
 * CVE-2013-2459
>
 * CVE-2013-2466
>
 * CVE-2013-2462
>
 * CVE-2013-2460
>
 * CVE-2013-3743
>
 * CVE-2013-2448
>
 * CVE-2013-2442
>
 * CVE-2013-2407
>
 * CVE-2013-2454
>
 * CVE-2013-2458
>
 * CVE-2013-3744
>
 * CVE-2013-2400
>
 * CVE-2013-2456
>
 * CVE-2013-2453
>
 * CVE-2013-2457
>
 * CVE-2013-2455
>
 * CVE-2013-2412
>
 * CVE-2013-2443
>
 * CVE-2013-2447
>
 * CVE-2013-2437
>
 * CVE-2013-2444
>
 * CVE-2013-2452
>
 * CVE-2013-2446
>
 * CVE-2013-2450
>
 * CVE-2013-1571
>
 * CVE-2013-2449
>
 * CVE-2013-2451
>
 * CVE-2013-1500
>");

  script_tag(name:"affected", value:"'java-1_7_0-ibm' package(s) on SUSE Linux Enterprise Java 11-SP2, SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Software Development Kit 11-SP2.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm", rpm:"java-1_7_0-ibm~1.7.0_sr5.0~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-alsa", rpm:"java-1_7_0-ibm-alsa~1.7.0_sr5.0~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-jdbc", rpm:"java-1_7_0-ibm-jdbc~1.7.0_sr5.0~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-plugin", rpm:"java-1_7_0-ibm-plugin~1.7.0_sr5.0~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);