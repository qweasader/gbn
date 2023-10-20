# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2017.3464.2");
  script_cve_id("CVE-2016-7098", "CVE-2017-13089", "CVE-2017-13090", "CVE-2017-6508");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-30 02:29:00 +0000 (Sat, 30 Dec 2017)");

  script_name("Ubuntu: Security Advisory (USN-3464-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3464-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3464-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wget' package(s) announced via the USN-3464-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3464-1 fixed several vulnerabilities in Wget. This update
provides the corresponding update for Ubuntu 12.04 ESM.

Original advisory details:

 Antti Levomaki, Christian Jalio, and Joonas Pihlaja discovered that Wget
 incorrectly handled certain HTTP responses. A remote attacker could use
 this issue to cause Wget to crash, resulting in a denial of service, or
 possibly execute arbitrary code. (CVE-2017-13089, CVE-2017-13090)

 Dawid Golunski discovered that Wget incorrectly handled recursive or
 mirroring mode. A remote attacker could possibly use this issue to bypass
 intended access list restrictions. (CVE-2016-7098)

 Orange Tsai discovered that Wget incorrectly handled CRLF sequences in
 HTTP headers. A remote attacker could possibly use this issue to inject
 arbitrary HTTP headers. (CVE-2017-6508)");

  script_tag(name:"affected", value:"'wget' package(s) on Ubuntu 12.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"wget", ver:"1.13.4-2ubuntu1.5", rls:"UBUNTU12.04 LTS"))) {
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
