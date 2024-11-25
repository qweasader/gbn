# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0005");
  script_cve_id("CVE-2022-35978");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-17 14:16:24 +0000 (Wed, 17 Aug 2022)");

  script_name("Mageia: Security Advisory (MGASA-2023-0005)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0005");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0005.html");
  script_xref(name:"URL", value:"https://blog.minetest.net/2022/08/04/5.6.0-released/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31363");
  script_xref(name:"URL", value:"https://dev.minetest.net/Changelog#5.4.0_.E2.86.92_5.5.0");
  script_xref(name:"URL", value:"https://dev.minetest.net/Changelog#5.5.0_.E2.86.92_5.6.0");
  script_xref(name:"URL", value:"https://dev.minetest.net/Changelog#5.6.0_.E2.86.92_5.6.1");
  script_xref(name:"URL", value:"https://github.com/minetest/minetest/security/advisories/GHSA-663q-pcjw-27cc");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'minetest' package(s) announced via the MGASA-2023-0005 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides minetest 5.6.1, the latest stable release of the open
source voxel game. This updates provides a number of feature and bug fix
changes compared to the previous version 5.4.0 provided in Mageia 8. See
the linked release notes and changelogs for details.

The update also improves compatibility with hosted game servers, which
typically run and expect the latest stable release.

The update also fixes a security vulnerability affecting single player
with malicious mods (GHSA-663q-pcjw-27cc)

In single player, a mod could set a global setting that controls the Lua
script loaded to display the main menu. The script would be loaded as soon
as the game session is exited. The Lua environment the menu runs in was
not sandboxed and could directly interfere with the user's system.
(CVE-2022-35978)");

  script_tag(name:"affected", value:"'minetest' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"minetest", rpm:"minetest~5.6.1~1.mga8", rls:"MAGEIA8"))) {
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
