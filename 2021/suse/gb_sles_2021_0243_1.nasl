# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0243.1");
  script_cve_id("CVE-2020-25649", "CVE-2020-35728", "CVE-2021-20190");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:45 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-22 19:28:54 +0000 (Fri, 22 Jan 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:0243-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:0243-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20210243-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jackson-databind' package(s) announced via the SUSE-SU-2021:0243-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for jackson-databind fixes the following issues:

jackson-databind was updated to 2.10.5.1:
 * #2589: `DOMDeserializer`: setExpandEntityReferences(false) may not
 prevent external entity expansion in all cases (CVE-2020-25649,
 bsc#1177616)
 * #2787 (partial fix): NPE after add mixin for enum
 * #2679: 'ObjectMapper.readValue('123', Void.TYPE)' throws 'should never
 occur'");

  script_tag(name:"affected", value:"'jackson-databind' package(s) on SUSE Linux Enterprise Module for Development Tools 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"jackson-databind", rpm:"jackson-databind~2.10.5.1~3.3.2", rls:"SLES15.0SP2"))) {
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
