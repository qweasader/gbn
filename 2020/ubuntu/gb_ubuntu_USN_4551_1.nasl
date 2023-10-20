# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844622");
  script_cve_id("CVE-2020-15049", "CVE-2020-15810", "CVE-2020-15811", "CVE-2020-24606");
  script_tag(name:"creation_date", value:"2020-09-29 03:01:32 +0000 (Tue, 29 Sep 2020)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-17 15:39:00 +0000 (Wed, 17 Mar 2021)");

  script_name("Ubuntu: Security Advisory (USN-4551-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4551-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4551-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid3' package(s) announced via the USN-4551-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alex Rousskov and Amit Klein discovered that Squid incorrectly handled
certain Content-Length headers. A remote attacker could possibly use this
issue to perform an HTTP request smuggling attack, resulting in cache
poisoning. (CVE-2020-15049)

Amit Klein discovered that Squid incorrectly validated certain data. A
remote attacker could possibly use this issue to perform an HTTP request
smuggling attack, resulting in cache poisoning. (CVE-2020-15810)

Regis Leroy discovered that Squid incorrectly validated certain data. A
remote attacker could possibly use this issue to perform an HTTP request
splitting attack, resulting in cache poisoning. (CVE-2020-15811)

Lubos Uhliarik discovered that Squid incorrectly handled certain Cache
Digest response messages sent by trusted peers. A remote attacker could
possibly use this issue to cause Squid to consume resources, resulting in a
denial of service. (CVE-2020-24606)");

  script_tag(name:"affected", value:"'squid3' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"squid", ver:"3.5.12-1ubuntu7.15", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"squid", ver:"3.5.27-1ubuntu1.9", rls:"UBUNTU18.04 LTS"))) {
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
