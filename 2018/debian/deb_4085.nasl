# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704085");
  script_cve_id("CVE-2018-0486");
  script_tag(name:"creation_date", value:"2018-01-11 23:00:00 +0000 (Thu, 11 Jan 2018)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-15 18:24:00 +0000 (Thu, 15 Feb 2018)");

  script_name("Debian: Security Advisory (DSA-4085-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-4085-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4085-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4085");
  script_xref(name:"URL", value:"https://shibboleth.net/community/advisories/secadv_20180112.txt");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/xmltooling");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xmltooling' package(s) announced via the DSA-4085-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Philip Huppert discovered the Shibboleth service provider is vulnerable to impersonation attacks and information disclosure due to mishandling of DTDs in the XMLTooling XML parsing library. For additional details please refer to the upstream advisory at [link moved to references]

For the oldstable distribution (jessie), this problem has been fixed in version 1.5.3-2+deb8u2.

The stable distribution (stretch) is not affected.

We recommend that you upgrade your xmltooling packages.

For the detailed security status of xmltooling please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'xmltooling' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libxmltooling-dev", ver:"1.5.3-2+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxmltooling-doc", ver:"1.5.3-2+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxmltooling6", ver:"1.5.3-2+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xmltooling-schemas", ver:"1.5.3-2+deb8u2", rls:"DEB8"))) {
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
