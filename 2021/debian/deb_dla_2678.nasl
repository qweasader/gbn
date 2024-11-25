# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892678");
  script_cve_id("CVE-2020-26247");
  script_tag(name:"creation_date", value:"2021-06-07 03:00:16 +0000 (Mon, 07 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-04 15:32:19 +0000 (Mon, 04 Jan 2021)");

  script_name("Debian: Security Advisory (DLA-2678-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2678-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2678-1");
  script_xref(name:"URL", value:"https://github.com/sparklemotion/nokogiri/security/advisories/GHSA-vr8q-g5c7-m54m");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ruby-nokogiri");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby-nokogiri' package(s) announced via the DLA-2678-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An XXE vulnerability was found in Nokogiri, a Rubygem providing HTML, XML, SAX, and Reader parsers with XPath and CSS selector support.

XML Schemas parsed by Nokogiri::XML::Schema were trusted by default, allowing external resources to be accessed over the network, potentially enabling XXE or SSRF attacks. The new default behavior is to treat all input as untrusted. The upstream advisory provides further information how to mitigate the problem or restore the old behavior again.

[link moved to references]

For Debian 9 stretch, this problem has been fixed in version 1.6.8.1-1+deb9u1.

We recommend that you upgrade your ruby-nokogiri packages.

For the detailed security status of ruby-nokogiri please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ruby-nokogiri' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"ruby-nokogiri", ver:"1.6.8.1-1+deb9u1", rls:"DEB9"))) {
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
