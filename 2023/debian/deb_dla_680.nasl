# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.680");
  script_cve_id("CVE-2016-7543");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-20 16:32:29 +0000 (Fri, 20 Jan 2017)");

  script_name("Debian: Security Advisory (DLA-680-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-680-2");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/DLA-680-2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bash' package(s) announced via the DLA-680-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An old attack vector has been corrected in bash, a sh-compatible command language interpreter.

CVE-2016-7543

Specially crafted SHELLOPTS+PS4 environment variables in combination with insecure setuid binaries can result in root privilege escalation.

The setuid binary had to both use setuid() function call in combination with a system() or popen() function call. With this combination it is possible to gain root access.

I addition bash have to be the default shell (/bin/sh have to point to bash) for the system to be vulnerable.

The default shell in Debian is dash and there are no known setuid binaries in Debian with the, above described, insecure combination.

There could however be local software with the, above described, insecure combination that could benefit from this correction.

For Debian 7 Wheezy, this problem have been fixed in version 4.2+dfsg-0.1+deb7u3.

We recommend that you upgrade your bash packages.

If there are local software that have the insecure combination and do a setuid() to some other user than root, then the update will not correct that problem. That problem have to be addressed in the insecure setuid binary.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'bash' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"bash", ver:"4.2+dfsg-0.1+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bash-builtins", ver:"4.2+dfsg-0.1+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bash-doc", ver:"4.2+dfsg-0.1+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bash-static", ver:"4.2+dfsg-0.1+deb7u4", rls:"DEB7"))) {
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
