# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2018.3535.2");
  script_cve_id("CVE-2017-3145");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2023-06-23T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-06-23 05:05:08 +0000 (Fri, 23 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-21 18:19:00 +0000 (Wed, 21 Jun 2023)");

  script_name("Ubuntu: Security Advisory (USN-3535-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3535-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3535-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind9' package(s) announced via the USN-3535-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3535-1 fixed a vulnerability in Bind. This update provides
the corresponding update for Ubuntu 12.04 ESM.

Original advisory details:

 Jayachandran Palanisamy discovered that the Bind resolver incorrectly
 handled fetch cleanup sequencing. A remote attacker could possibly use this
 issue to cause Bind to crash, resulting in a denial of service.");

  script_tag(name:"affected", value:"'bind9' package(s) on Ubuntu 12.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.8.1.dfsg.P1-4ubuntu0.24", rls:"UBUNTU12.04 LTS"))) {
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
