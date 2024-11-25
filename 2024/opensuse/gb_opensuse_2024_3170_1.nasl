# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856455");
  script_version("2024-09-25T05:06:11+0000");
  script_cve_id("CVE-2024-7348");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-12 15:54:52 +0000 (Mon, 12 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-09-11 04:00:27 +0000 (Wed, 11 Sep 2024)");
  script_name("openSUSE: Security Advisory for postgresql16 (SUSE-SU-2024:3170-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3170-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/Y2ZSBWE2P3VPRYADHRVVYBGOKQRNZ3JW");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql16'
  package(s) announced via the SUSE-SU-2024:3170-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql16 fixes the following issues:

  * Upgrade to 16.4 (bsc#1229013)

  * CVE-2024-7348: PostgreSQL relation replacement during pg_dump executes
      arbitrary SQL. (bsc#1229013)

  ##");

  script_tag(name:"affected", value:"'postgresql16' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-plperl-debuginfo", rpm:"postgresql16-plperl-debuginfo~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-devel-mini", rpm:"postgresql16-devel-mini~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-debuginfo", rpm:"postgresql16-debuginfo~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16", rpm:"postgresql16~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-llvmjit-devel", rpm:"postgresql16-llvmjit-devel~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-pltcl", rpm:"postgresql16-pltcl~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-devel-debuginfo", rpm:"postgresql16-devel-debuginfo~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-server-devel", rpm:"postgresql16-server-devel~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-llvmjit-debuginfo", rpm:"postgresql16-llvmjit-debuginfo~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-debuginfo", rpm:"libecpg6-debuginfo~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-test", rpm:"postgresql16-test~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-plpython", rpm:"postgresql16-plpython~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-plpython-debuginfo", rpm:"postgresql16-plpython-debuginfo~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6", rpm:"libecpg6~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-pltcl-debuginfo", rpm:"postgresql16-pltcl-debuginfo~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-plperl", rpm:"postgresql16-plperl~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-debuginfo", rpm:"libpq5-debuginfo~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-contrib-debuginfo", rpm:"postgresql16-contrib-debuginfo~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-devel-mini-debuginfo", rpm:"postgresql16-devel-mini-debuginfo~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-contrib", rpm:"postgresql16-contrib~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-server-devel-debuginfo", rpm:"postgresql16-server-devel-debuginfo~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-mini-debugsource", rpm:"postgresql16-mini-debugsource~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-server-debuginfo", rpm:"postgresql16-server-debuginfo~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-devel", rpm:"postgresql16-devel~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-debugsource", rpm:"postgresql16-debugsource~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-server", rpm:"postgresql16-server~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-llvmjit", rpm:"postgresql16-llvmjit~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit-debuginfo", rpm:"libpq5-32bit-debuginfo~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-32bit", rpm:"libecpg6-32bit~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-32bit-debuginfo", rpm:"libecpg6-32bit-debuginfo~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit", rpm:"libpq5-32bit~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-docs", rpm:"postgresql16-docs~16.4~150200.5.16.1", rls:"openSUSELeap15.5"))) {
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