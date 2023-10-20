# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705334");
  script_cve_id("CVE-2022-45060");
  script_tag(name:"creation_date", value:"2023-01-30 02:00:04 +0000 (Mon, 30 Jan 2023)");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-09 19:49:00 +0000 (Wed, 09 Nov 2022)");

  script_name("Debian: Security Advisory (DSA-5334)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5334");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5334");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5334");
  script_xref(name:"URL", value:"https://varnish-cache.org/security/VSV00011.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/varnish");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'varnish' package(s) announced via the DSA-5334 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Martin van Kervel Smedshammer discovered that varnish, a state of the art, high-performance web accelerator, is prone to a HTTP/2 request forgery vulnerability.

See [link moved to references] for details.

For the stable distribution (bullseye), this problem has been fixed in version 6.5.1-1+deb11u3.

We recommend that you upgrade your varnish packages.

For the detailed security status of varnish please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'varnish' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libvarnishapi-dev", ver:"6.5.1-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvarnishapi2", ver:"6.5.1-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"varnish", ver:"6.5.1-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"varnish-doc", ver:"6.5.1-1+deb11u3", rls:"DEB11"))) {
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
