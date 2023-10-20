# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0188.2");
  script_cve_id("CVE-2013-0200", "CVE-2013-4325", "CVE-2013-6402");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:22 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0188-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0188-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140188-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hplip' package(s) announced via the SUSE-SU-2014:0188-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"hplip was updated to fix three security issues:

 *

 CVE-2013-0200: Some local file overwrite problems via predictable /tmp filenames were fixed.

 *

 CVE-2013-4325: hplip used an insecure polkit DBUS API
(polkit-process subject race condition) which could lead to local privilege escalation.

 *

 CVE-2013-6402: hplip uses arbitrary file creation/overwrite (via hardcoded file name
/tmp/hp-pkservice.log).

Security Issue references:

 * CVE-2013-4325
>
 * CVE-2013-0200
>
 * CVE-2013-6402
>");

  script_tag(name:"affected", value:"'hplip' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"hplip", rpm:"hplip~3.11.10~0.6.11.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-hpijs", rpm:"hplip-hpijs~3.11.10~0.6.11.1", rls:"SLES11.0SP3"))) {
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
