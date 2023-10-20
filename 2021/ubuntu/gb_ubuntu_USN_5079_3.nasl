# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845067");
  script_cve_id("CVE-2021-22945", "CVE-2021-22946", "CVE-2021-22947");
  script_tag(name:"creation_date", value:"2021-09-22 01:00:38 +0000 (Wed, 22 Sep 2021)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-08 15:51:00 +0000 (Fri, 08 Oct 2021)");

  script_name("Ubuntu: Security Advisory (USN-5079-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5079-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5079-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1944120");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the USN-5079-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5079-1 fixed vulnerabilities in curl. One of the fixes introduced a
regression on Ubuntu 18.04 LTS. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that curl incorrect handled memory when sending data to
 an MQTT server. A remote attacker could use this issue to cause curl to
 crash, resulting in a denial of service, or possibly execute arbitrary
 code. (CVE-2021-22945)

 Patrick Monnerat discovered that curl incorrectly handled upgrades to TLS.
 When receiving certain responses from servers, curl would continue without
 TLS even when the option to require a successful upgrade to TLS was
 specified. (CVE-2021-22946)

 Patrick Monnerat discovered that curl incorrectly handled responses
 received before STARTTLS. A remote attacker could possibly use this issue
 to inject responses and intercept communications. (CVE-2021-22947)");

  script_tag(name:"affected", value:"'curl' package(s) on Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"curl", ver:"7.58.0-2ubuntu3.16", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.58.0-2ubuntu3.16", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.58.0-2ubuntu3.16", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl4", ver:"7.58.0-2ubuntu3.16", rls:"UBUNTU18.04 LTS"))) {
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
