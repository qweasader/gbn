# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.633");
  script_cve_id("CVE-2015-8834", "CVE-2016-4029", "CVE-2016-5836", "CVE-2016-6634", "CVE-2016-6635", "CVE-2016-7168", "CVE-2016-7169");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-08-10 15:20:06 +0000 (Wed, 10 Aug 2016)");

  script_name("Debian: Security Advisory (DLA-633-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-633-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/DLA-633-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wordpress' package(s) announced via the DLA-633-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in wordpress, a web blogging tool. The Common Vulnerabilities and Exposures project identifies the following issues.

CVE-2015-8834

Cross-site scripting (XSS) vulnerability in wp-includes/wp-db.php in WordPress before 4.2.2 allows remote attackers to inject arbitrary web script or HTML via a long comment that is improperly stored because of limitations on the MySQL TEXT data type. NOTE: this vulnerability exists because of an incomplete fix for CVE-2015-3440

CVE-2016-4029

WordPress before 4.5 does not consider octal and hexadecimal IP address formats when determining an intranet address, which allows remote attackers to bypass an intended SSRF protection mechanism via a crafted address.

CVE-2016-5836

The oEmbed protocol implementation in WordPress before 4.5.3 allows remote attackers to cause a denial of service via unspecified vectors.

CVE-2016-6634

Cross-site scripting (XSS) vulnerability in the network settings page in WordPress before 4.5 allows remote attackers to inject arbitrary web script or HTML via unspecified vectors.

CVE-2016-6635

Cross-site request forgery (CSRF) vulnerability in the wp_ajax_wp_compression_test function in wp-admin/includes/ajaxactions.php in WordPress before 4.5 allows remote attackers to hijack the authentication of administrators for requests that change the script compression option.

CVE-2016-7168

Fix a cross-site scripting vulnerability via image filename.

CVE-2016-7169

Fix a path traversal vulnerability in the upgrade package uploader.

For Debian 7 Wheezy, these problems have been fixed in version 3.6.1+dfsg-1~deb7u12.

We recommend that you upgrade your wordpress packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"3.6.1+dfsg-1~deb7u12", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"3.6.1+dfsg-1~deb7u12", rls:"DEB7"))) {
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
