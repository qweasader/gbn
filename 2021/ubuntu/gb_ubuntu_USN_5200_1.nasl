# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845173");
  script_cve_id("CVE-2020-8492", "CVE-2021-3733", "CVE-2021-3737");
  script_tag(name:"creation_date", value:"2021-12-18 02:00:29 +0000 (Sat, 18 Dec 2021)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-15 17:01:12 +0000 (Tue, 15 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-5200-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5200-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5200-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.7, python3.8' package(s) announced via the USN-5200-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the urllib.request.AbstractBasicAuthHandler class
in Python contains regex allowing for catastrophic backtracking. Specially
crafted traffic from a malicious HTTP server could cause a regular expression
denial of service (ReDoS) condition for a client.
(CVE-2020-8492)

It was discovered that the urllib.request.AbstractBasicAuthHandler class
in Python contains regex with a quadratic worst-case time complexity.
Specially crafted traffic from a malicious HTTP server could cause a regular
expression denial of service (ReDoS) condition for a client.
(CVE-2021-3733)

It was discovered that the Python urllib http client could enter into an infinite
loop when incorrectly handling certain server responses (100 Continue response).
Specially crafted traffic from a malicious HTTP server could cause a denial of
service (DoS) condition for a client.
(CVE-2021-3737)");

  script_tag(name:"affected", value:"'python3.7, python3.8' package(s) on Ubuntu 18.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libpython3.7-stdlib", ver:"3.7.5-2ubuntu1~18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpython3.8-stdlib", ver:"3.8.0-3ubuntu1~18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.7", ver:"3.7.5-2ubuntu1~18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.7-minimal", ver:"3.7.5-2ubuntu1~18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.8", ver:"3.8.0-3ubuntu1~18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.8-minimal", ver:"3.8.0-3ubuntu1~18.04.2", rls:"UBUNTU18.04 LTS"))) {
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
