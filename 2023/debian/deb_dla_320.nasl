# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.320");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-01-12T16:12:12+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:12 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-320-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-320-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/DLA-320-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libemail-address-perl' package(s) announced via the DLA-320-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pali Rohar discovered a possible DoS attack in any software which uses the Email::Address Perl module for parsing string input to a list of email addresses.

By default Email::Address module, version v1.907 (and all before) tries to understand nestable comments in an input string with depth level 2.

With specially crafted inputs, parsing nestable comments can become too slow and can cause high CPU load, freeze the application and end in Denial of Service.

Because input strings for Email::Address module come from external sources (e.g. from email sent by an attacker) it is a security problem impacting on all software applications which parse email messages using the Email::Address Perl module.

With this upload of libemail-address-perl, the default value of nestable comments has been set to depth level 1 (as proposed by upstream). Please note that this is not proper a fix, just a workaround for pathological inputs with nestable comments.");

  script_tag(name:"affected", value:"'libemail-address-perl' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libemail-address-perl", ver:"1.889-2+deb6u2", rls:"DEB6"))) {
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
