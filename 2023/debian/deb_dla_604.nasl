# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.604");
  script_cve_id("CVE-2015-7576", "CVE-2016-0751", "CVE-2016-0752", "CVE-2016-2097", "CVE-2016-2098", "CVE-2016-6316");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-01-12T16:12:12+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:12 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-08 15:43:00 +0000 (Thu, 08 Aug 2019)");

  script_name("Debian: Security Advisory (DLA-604-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-604-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/DLA-604-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby-actionpack-3.2' package(s) announced via the DLA-604-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in ruby-actionpack-3.2, a web-flow and rendering framework and part of Rails:

CVE-2015-7576

A flaw was found in the way the Action Controller component compared user names and passwords when performing HTTP basic authentication. Time taken to compare strings could differ depending on input, possibly allowing a remote attacker to determine valid user names and passwords using a timing attack.

CVE-2016-0751

A flaw was found in the way the Action Pack component performed MIME type lookups. Since queries were cached in a global cache of MIME types, an attacker could use this flaw to grow the cache indefinitely, potentially resulting in a denial of service.

CVE-2016-0752

A directory traversal flaw was found in the way the Action View component searched for templates for rendering. If an application passed untrusted input to the render method, a remote, unauthenticated attacker could use this flaw to render unexpected files and, possibly, execute arbitrary code.

CVE-2016-2097

Crafted requests to Action View might result in rendering files from arbitrary locations, including files beyond the application's view directory. This vulnerability is the result of an incomplete fix of CVE-2016-0752. This bug was found by Jyoti Singh and Tobias Kraze from Makandra.

CVE-2016-2098

If a web applications does not properly sanitize user inputs, an attacker might control the arguments of the render method in a controller or a view, resulting in the possibility of executing arbitrary ruby code. This bug was found by Tobias Kraze from Makandra and joernchen of Phenoelit.

CVE-2016-6316

Andrew Carpenter of Critical Juncture discovered a cross-site scripting vulnerability affecting Action View. Text declared as HTML safe will not have quotes escaped when used as attribute values in tag helpers.

For Debian 7 Wheezy, these problems have been fixed in version 3.2.6-6+deb7u3.

We recommend that you upgrade your ruby-actionpack-3.2 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ruby-actionpack-3.2' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ruby-actionpack-3.2", ver:"3.2.6-6+deb7u3", rls:"DEB7"))) {
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
