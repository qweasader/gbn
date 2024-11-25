# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2021.4813.1");
  script_cve_id("CVE-2018-11307", "CVE-2018-12022", "CVE-2018-12023", "CVE-2018-14718", "CVE-2018-14719", "CVE-2018-14720", "CVE-2018-14721", "CVE-2018-19360", "CVE-2018-19361", "CVE-2018-19362", "CVE-2019-12086", "CVE-2019-12384", "CVE-2019-12814", "CVE-2019-14379", "CVE-2019-14439", "CVE-2019-14540", "CVE-2019-16335", "CVE-2019-16942", "CVE-2019-16943", "CVE-2019-17267", "CVE-2019-17531", "CVE-2019-20330", "CVE-2020-10672", "CVE-2020-10673", "CVE-2020-10968", "CVE-2020-10969", "CVE-2020-11111", "CVE-2020-11112", "CVE-2020-11113", "CVE-2020-11619", "CVE-2020-11620", "CVE-2020-14060", "CVE-2020-14061", "CVE-2020-14062", "CVE-2020-14195", "CVE-2020-8840", "CVE-2020-9546", "CVE-2020-9547", "CVE-2020-9548");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-19 17:28:26 +0000 (Wed, 19 Feb 2020)");

  script_name("Ubuntu: Security Advisory (USN-4813-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4813-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4813-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jackson-databind' package(s) announced via the USN-4813-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Jackson Databind incorrectly handled
deserialization. An attacker could possibly use this issue to obtain
sensitive information. (CVE-2018-11307, CVE-2019-12086, CVE-2019-12814)

It was discovered that Jackson Databind incorrectly handled
deserialization. An attacker could possibly use this issue to execute
arbitrary code or other unspecified impact. (CVE-2018-12022,
CVE-2018-12023, CVE-2018-14718, CVE-2018-14719, CVE-2018-19360,
CVE-2018-19361, CVE-2018-19362, CVE-2019-12384, CVE-2019-14379,
CVE-2019-14439, CVE-2019-14540, CVE-2019-16335, CVE-2019-16942,
CVE-2019-16943, CVE-2019-17267, CVE-2019-17531, CVE-2019-20330,
CVE-2020-10672, CVE-2020-10673, CVE-2020-10968, CVE-2020-10969,
CVE-2020-11111, CVE-2020-11112, CVE-2020-11113, CVE-2020-11619,
CVE-2020-11620, CVE-2020-14060, CVE-2020-14061, CVE-2020-14062,
CVE-2020-14195, CVE-2020-8840, CVE-2020-9546, CVE-2020-9547, CVE-2020-9548)

It was discovered that Jackson Databind incorrectly handled
deserialization. An attacker could possibly use this issue to execute XML
entity (XXE) attacks. (CVE-2018-14720)

It was discovered that Jackson Databind incorrectly handled
deserialization. An attacker could possibly use this issue to execute
server-side request forgery (SSRF). (CVE-2018-14721)");

  script_tag(name:"affected", value:"'jackson-databind' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libjackson2-databind-java", ver:"2.4.2-3ubuntu0.1~esm2", rls:"UBUNTU16.04 LTS"))) {
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
