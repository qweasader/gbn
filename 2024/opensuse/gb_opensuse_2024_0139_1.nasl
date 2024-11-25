# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856164");
  script_version("2024-06-07T15:38:39+0000");
  script_cve_id("CVE-2023-50471", "CVE-2023-50472", "CVE-2024-31755");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-06-07 15:38:39 +0000 (Fri, 07 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-19 20:53:28 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-05-26 01:00:21 +0000 (Sun, 26 May 2024)");
  script_name("openSUSE: Security Advisory for cJSON (openSUSE-SU-2024:0139-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0139-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/36QNMKFWNRJX3XHLNGZ3DNLMLIHSRF4U");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cJSON'
  package(s) announced via the openSUSE-SU-2024:0139-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cJSON fixes the following issues:

  - Update to 1.7.18:

  * CVE-2024-31755: NULL pointer dereference via cJSON_SetValuestring()
         (boo#1223420)

  * Remove non-functional list handling of compiler flags

  * Fix heap buffer overflow

  * remove misused optimization flag -01

  * Set free'd pointers to NULL whenever they are not reassigned
         immediately after

  - Update to version 1.7.17 (boo#1218098, CVE-2023-50472, boo#1218099,
       CVE-2023-50471):

  * Fix null reference in cJSON_SetValuestring (CVE-2023-50472).

  * Fix null reference in cJSON_InsertItemInArray (CVE-2023-50471).

  - Update to 1.7.16:

  * Add an option for ENABLE_CJSON_VERSION_SO in CMakeLists.txt

  * Add cmake_policy to CMakeLists.txt

  * Add cJSON_SetBoolValue

  * Add meson documentation

  * Fix memory leak in merge_patch

  * Fix conflicting target names 'uninstall'

  * Bump cmake version to 3.0 and use new version syntax

  * Print int without decimal places

  * Fix 'cjson_utils-static' target not exist

  * Add allocate check for replace_item_in_object

  * Fix a null pointer crash in cJSON_ReplaceItemViaPointer");

  script_tag(name:"affected", value:"'cJSON' package(s) on openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"cJSON-devel", rpm:"cJSON-devel~1.7.18~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcjson1", rpm:"libcjson1~1.7.18~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cJSON-devel", rpm:"cJSON-devel~1.7.18~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcjson1", rpm:"libcjson1~1.7.18~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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