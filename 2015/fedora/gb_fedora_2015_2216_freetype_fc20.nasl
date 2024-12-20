# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.869027");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2015-02-21 05:39:58 +0100 (Sat, 21 Feb 2015)");
  script_cve_id("CVE-2014-9656", "CVE-2014-9657", "CVE-2014-9658", "CVE-2014-9675",
                "CVE-2014-9660", "CVE-2014-9661", "CVE-2014-9662", "CVE-2014-9663",
                "CVE-2014-9664", "CVE-2014-9666", "CVE-2014-9667", "CVE-2014-9669",
                "CVE-2014-9670", "CVE-2014-9671", "CVE-2014-9672", "CVE-2014-9673",
                "CVE-2014-9674", "CVE-2014-2240", "CVE-2014-2241", "CVE-2014-9659",
                "CVE-2014-9665", "CVE-2014-9668");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for freetype FEDORA-2015-2216");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'freetype'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"freetype on Fedora 20");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2015-2216");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-February/150162.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC20");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC20")
{

  if ((res = isrpmvuln(pkg:"freetype", rpm:"freetype~2.5.0~9.fc20", rls:"FC20")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
