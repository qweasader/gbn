# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704829");
  script_cve_id("CVE-2020-26262");
  script_tag(name:"creation_date", value:"2021-01-12 04:00:09 +0000 (Tue, 12 Jan 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-20 03:15:00 +0000 (Wed, 20 Jan 2021)");

  script_name("Debian: Security Advisory (DSA-4829)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4829");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4829");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4829");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/coturn");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'coturn' package(s) announced via the DSA-4829 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was discovered in coturn, a TURN and STUN server for VoIP. By default coturn does not allow peers on the loopback addresses (127.x.x.x and ::1). A remote attacker can bypass the protection via a specially crafted request using a peer address of 0.0.0.0 and trick coturn in relaying to the loopback interface. If listening on IPv6 the loopback interface can also be reached by using either [::1] or [::] as the address.

For the stable distribution (buster), this problem has been fixed in version 4.5.1.1-1.1+deb10u2.

We recommend that you upgrade your coturn packages.

For the detailed security status of coturn please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'coturn' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"coturn", ver:"4.5.1.1-1.1+deb10u2", rls:"DEB10"))) {
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
