# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.1074");
  script_cve_id("CVE-2021-33560");
  script_tag(name:"creation_date", value:"2022-02-13 03:23:50 +0000 (Sun, 13 Feb 2022)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-01 06:15:00 +0000 (Thu, 01 Jul 2021)");

  script_name("Huawei EulerOS: Security Advisory for libgcrypt (EulerOS-SA-2022-1074)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-1074");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1074");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libgcrypt' package(s) announced via the EulerOS-SA-2022-1074 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Libgcrypt before 1.8.8 and 1.9.x before 1.9.3 mishandles ElGamal encryption because it lacks exponent blinding to address a side-channel attack against mpi_powm, and the window size is not chosen appropriately. (There is also an interoperability problem because the selection of the k integer value does not properly consider the differences between basic ElGamal encryption and generalized ElGamal encryption.) This, for example, affects use of ElGamal in OpenPGP.(CVE-2021-33560)");

  script_tag(name:"affected", value:"'libgcrypt' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0.");

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

if(release == "EULEROSVIRTARM64-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt", rpm:"libgcrypt~1.8.3~3.h4.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt-devel", rpm:"libgcrypt-devel~1.8.3~3.h4.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
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
