# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3688");
  script_cve_id("CVE-2023-45539");
  script_tag(name:"creation_date", value:"2023-12-15 04:21:33 +0000 (Fri, 15 Dec 2023)");
  script_version("2024-01-12T16:12:12+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:12 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-04 19:32:00 +0000 (Mon, 04 Dec 2023)");

  script_name("Debian: Security Advisory (DLA-3688-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3688-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3688-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'haproxy' package(s) announced via the DLA-3688-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a potential information disclosure vulnerability in HAProxy, a reverse proxy server used to load balance HTTP requests across multiple servers.

HAProxy formerly accepted the # (ie. the 'pound' or 'hash') symbol as part of a URI component. This might have allowed remote attackers to obtain sensitive information upon HAProxy's misinterpretation of a path_end rule, such as by routing index.html#.png to a static server.

CVE-2023-45539

HAProxy before 2.8.2 accepts # as part of the URI component, which might allow remote attackers to obtain sensitive information or have unspecified other impact upon misinterpretation of a path_end rule, such as routing index.html#.png to a static server.

For Debian 10 Buster, this problem has been fixed in version 1.8.19-1+deb10u5.

We recommend that you upgrade your haproxy packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'haproxy' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"haproxy", ver:"1.8.19-1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"haproxy-doc", ver:"1.8.19-1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-haproxy", ver:"1.8.19-1+deb10u5", rls:"DEB10"))) {
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
