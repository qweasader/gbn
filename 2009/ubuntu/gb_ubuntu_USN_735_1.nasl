# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63621");
  script_cve_id("CVE-2009-0586");
  script_tag(name:"creation_date", value:"2009-03-19 23:52:38 +0000 (Thu, 19 Mar 2009)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-735-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU8\.10");

  script_xref(name:"Advisory-ID", value:"USN-735-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-735-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gst-plugins-base0.10' package(s) announced via the USN-735-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Base64 decoding functions in GStreamer Base
Plugins did not properly handle large images in Vorbis file tags. If a user
were tricked into opening a specially crafted Vorbis file, an attacker
could possibly execute arbitrary code with user privileges.");

  script_tag(name:"affected", value:"'gst-plugins-base0.10' package(s) on Ubuntu 8.10.");

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

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer0.10-plugins-base", ver:"0.10.21-3ubuntu0.1", rls:"UBUNTU8.10"))) {
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
