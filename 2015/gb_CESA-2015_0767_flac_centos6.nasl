# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882157");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-04-02 07:12:28 +0200 (Thu, 02 Apr 2015)");
  script_cve_id("CVE-2014-8962", "CVE-2014-9028");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for flac CESA-2015:0767 centos6");
  script_tag(name:"summary", value:"Check the version of flac");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flac packages contain a decoder and an encoder for the FLAC (Free
Lossless Audio Codec) audio file format.

A buffer overflow flaw was found in the way flac decoded FLAC audio files.
An attacker could create a specially crafted FLAC audio file that could
cause an application using the flac library to crash or execute arbitrary
code when the file was read. (CVE-2014-9028)

A buffer over-read flaw was found in the way flac processed certain ID3v2
metadata. An attacker could create a specially crafted FLAC audio file that
could cause an application using the flac library to crash when the file
was read. (CVE-2014-8962)

All flac users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing the
update, all applications linked against the flac library must be restarted
for this update to take effect.");
  script_tag(name:"affected", value:"flac on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"CESA", value:"2015:0767");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-March/021008.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"flac", rpm:"flac~1.2.1~7.el6_6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"flac-devel", rpm:"flac-devel~1.2.1~7.el6_6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}