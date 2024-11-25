# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0137");
  script_cve_id("CVE-2018-21015", "CVE-2018-21016", "CVE-2019-13618", "CVE-2019-20161", "CVE-2019-20162", "CVE-2019-20163", "CVE-2019-20165", "CVE-2019-20170", "CVE-2019-20171", "CVE-2019-20208");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-17 18:09:46 +0000 (Wed, 17 Jul 2019)");

  script_name("Mageia: Security Advisory (MGASA-2020-0137)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0137");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0137.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26131");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2072");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gpac' package(s) announced via the MGASA-2020-0137 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:

AVC_DuplicateConfig() at isomedia/avc_ext.c in GPAC 0.7.1 allows remote
attackers to cause a denial of service (NULL pointer dereference and
application crash) via a crafted file.
There is 'cfg_new->AVCLevelIndication = cfg->AVCLevelIndication,' but
cfg could be NULL. (CVE-2018-21015)

audio_sample_entry_AddBox() at isomedia/box_code_base.c in GPAC 0.7.1
allows remote attackers to cause a denial of service (heap-based buffer
over-read and application crash) via a crafted file. (CVE-2018-21016)

In GPAC before 0.8.0, isomedia/isom_read.c in libgpac.a has a heap-based
buffer over-read, as demonstrated by a crash in gf_m2ts_sync in
media_tools/mpegts.c. (CVE-2019-13618)

An issue was discovered in GPAC version 0.8.0 and 0.9.0-development-
20191109. There is heap-based buffer overflow in the function
ReadGF_IPMPX_WatermarkingInit() in odf/ipmpx_code.c. (CVE-2019-20161)

An issue was discovered in GPAC version 0.8.0 and 0.9.0-development-
20191109. There is heap-based buffer overflow in the function
gf_isom_box_parse_ex() in isomedia/box_funcs.c. (CVE-2019-20162)

An issue was discovered in GPAC version 0.8.0 and 0.9.0-development-
20191109. There is a NULL pointer dereference in the function
gf_odf_avc_cfg_write_bs() in odf/descriptors.c. (CVE-2019-20163)

An issue was discovered in GPAC version 0.8.0 and 0.9.0-development-
20191109. There is a NULL pointer dereference in the function
ilst_item_Read() in isomedia/box_code_apple.c. (CVE-2019-20165)

An issue was discovered in GPAC version 0.8.0 and 0.9.0-development-
20191109. There is an invalid pointer dereference in the function
GF_IPMPX_AUTH_Delete() in odf/ipmpx_code.c. (CVE-2019-20170)

An issue was discovered in GPAC version 0.8.0 and 0.9.0-development-
20191109. There are memory leaks in metx_New in isomedia/box_code_base.c
and abst_Read in isomedia/box_code_adobe.c. (CVE-2019-20171)

dimC_Read in isomedia/box_code_3gpp.c in GPAC 0.8.0 has a stack-based
buffer overflow. (CVE-2019-20208)");

  script_tag(name:"affected", value:"'gpac' package(s) on Mageia 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"gpac", rpm:"gpac~0.7.1~6.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gpac-devel", rpm:"lib64gpac-devel~0.7.1~6.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gpac7", rpm:"lib64gpac7~0.7.1~6.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpac-devel", rpm:"libgpac-devel~0.7.1~6.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpac7", rpm:"libgpac7~0.7.1~6.1.mga7.tainted", rls:"MAGEIA7"))) {
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
