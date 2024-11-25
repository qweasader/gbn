# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833540");
  script_version("2024-05-16T05:05:35+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-32731", "CVE-2023-32732", "CVE-2023-33953", "CVE-2023-44487", "CVE-2023-4785");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-19 16:02:53 +0000 (Tue, 19 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 12:50:55 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for abseil (SUSE-SU-2024:0573-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5|openSUSELeapMicro5\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0573-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/A335QSYHJ3DSMHQJB4PZLCVP3IMMYCTE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'abseil'
  package(s) announced via the SUSE-SU-2024:0573-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for abseil-cpp, grpc, opencensus-proto, protobuf, python-abseil,
  python-grpcio, re2 fixes the following issues:

  abseil-cpp was updated to:

  Update to 20230802.1:

  * Add StdcppWaiter to the end of the list of waiter implementations

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'abseil' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"python311-grpcio-debuginfo", rpm:"python311-grpcio-debuginfo~1.60.0~150400.9.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0", rpm:"libprotobuf-lite25_1_0~25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-java", rpm:"protobuf-java~25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf25_1_0", rpm:"libprotobuf25_1_0~25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgrpc37-debuginfo", rpm:"libgrpc37-debuginfo~1.60.0~150400.8.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libupb37-debuginfo", rpm:"libupb37-debuginfo~1.60.0~150400.8.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grpc-debugsource", rpm:"grpc-debugsource~1.60.0~150400.8.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabsl2308_0_0-debuginfo", rpm:"libabsl2308_0_0-debuginfo~20230802.1~150400.10.4.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-debugsource", rpm:"protobuf-debugsource~25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabsl2308_0_0", rpm:"libabsl2308_0_0~20230802.1~150400.10.4.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgrpc1_60", rpm:"libgrpc1_60~1.60.0~150400.8.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-protobuf", rpm:"python311-protobuf~4.25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libupb37", rpm:"libupb37~1.60.0~150400.8.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2-11-20240201", rpm:"libre2-11-20240201~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grpc-devel", rpm:"grpc-devel~1.60.0~150400.8.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-grpcio", rpm:"python311-grpcio~1.60.0~150400.9.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-devel-debuginfo", rpm:"protobuf-devel-debuginfo~25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-grpcio-debugsource", rpm:"python-grpcio-debugsource~1.60.0~150400.9.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"re2-debugsource-20240201", rpm:"re2-debugsource-20240201~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf25_1_0-debuginfo", rpm:"libprotobuf25_1_0-debuginfo~25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abseil-cpp-debugsource", rpm:"abseil-cpp-debugsource~20230802.1~150400.10.4.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"upb-devel", rpm:"upb-devel~1.60.0~150400.8.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2-11-debuginfo-20240201", rpm:"libre2-11-debuginfo-20240201~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgrpc++1_60-debuginfo", rpm:"libgrpc++1_60-debuginfo~1.60.0~150400.8.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgrpc++1_60", rpm:"libgrpc++1_60~1.60.0~150400.8.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grpc-debuginfo", rpm:"grpc-debuginfo~1.60.0~150400.8.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgrpc1_60-debuginfo", rpm:"libgrpc1_60-debuginfo~1.60.0~150400.8.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"re2-devel-20240201", rpm:"re2-devel-20240201~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc25_1_0-debuginfo", rpm:"libprotoc25_1_0-debuginfo~25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-devel", rpm:"protobuf-devel~25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc25_1_0", rpm:"libprotoc25_1_0~25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0-debuginfo", rpm:"libprotobuf-lite25_1_0-debuginfo~25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgrpc37", rpm:"libgrpc37~1.60.0~150400.8.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abseil-cpp-devel", rpm:"abseil-cpp-devel~20230802.1~150400.10.4.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grpc-devel-debuginfo", rpm:"grpc-devel-debuginfo~1.60.0~150400.8.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2-11-32bit-debuginfo-20240201", rpm:"libre2-11-32bit-debuginfo-20240201~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2-11-32bit-20240201", rpm:"libre2-11-32bit-20240201~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0-32bit", rpm:"libprotobuf-lite25_1_0-32bit~25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabsl2308_0_0-32bit-debuginfo", rpm:"libabsl2308_0_0-32bit-debuginfo~20230802.1~150400.10.4.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0-32bit-debuginfo", rpm:"libprotobuf-lite25_1_0-32bit-debuginfo~25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf25_1_0-32bit-debuginfo", rpm:"libprotobuf25_1_0-32bit-debuginfo~25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc25_1_0-32bit", rpm:"libprotoc25_1_0-32bit~25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc25_1_0-32bit-debuginfo", rpm:"libprotoc25_1_0-32bit-debuginfo~25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabsl2308_0_0-32bit", rpm:"libabsl2308_0_0-32bit~20230802.1~150400.10.4.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf25_1_0-32bit", rpm:"libprotobuf25_1_0-32bit~25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grpc-source", rpm:"grpc-source~1.60.0~150400.8.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-abseil", rpm:"python311-abseil~1.4.0~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opencensus-proto-source", rpm:"opencensus-proto-source~0.3.0+git.20200721~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabsl2308_0_0-64bit", rpm:"libabsl2308_0_0-64bit~20230802.1~150400.10.4.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0-64bit", rpm:"libprotobuf-lite25_1_0-64bit~25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc25_1_0-64bit-debuginfo", rpm:"libprotoc25_1_0-64bit-debuginfo~25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf25_1_0-64bit", rpm:"libprotobuf25_1_0-64bit~25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf25_1_0-64bit-debuginfo", rpm:"libprotobuf25_1_0-64bit-debuginfo~25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc25_1_0-64bit", rpm:"libprotoc25_1_0-64bit~25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0-64bit-debuginfo", rpm:"libprotobuf-lite25_1_0-64bit-debuginfo~25.1~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabsl2308_0_0-64bit-debuginfo", rpm:"libabsl2308_0_0-64bit-debuginfo~20230802.1~150400.10.4.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2-11-64bit-debuginfo-20240201", rpm:"libre2-11-64bit-debuginfo-20240201~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2-11-64bit-20240201", rpm:"libre2-11-64bit-20240201~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }


  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"python311-grpcio-debuginfo", rpm:"python311-grpcio-debuginfo~1.60.0~150400.9.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0", rpm:"libprotobuf-lite25_1_0~25.1~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-java", rpm:"protobuf-java~25.1~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf25_1_0", rpm:"libprotobuf25_1_0~25.1~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgrpc37-debuginfo", rpm:"libgrpc37-debuginfo~1.60.0~150400.8.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libupb37-debuginfo", rpm:"libupb37-debuginfo~1.60.0~150400.8.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grpc-debugsource", rpm:"grpc-debugsource~1.60.0~150400.8.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabsl2308_0_0-debuginfo", rpm:"libabsl2308_0_0-debuginfo~20230802.1~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-debugsource", rpm:"protobuf-debugsource~25.1~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabsl2308_0_0", rpm:"libabsl2308_0_0~20230802.1~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgrpc1_60", rpm:"libgrpc1_60~1.60.0~150400.8.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-protobuf", rpm:"python311-protobuf~4.25.1~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libupb37", rpm:"libupb37~1.60.0~150400.8.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2-11-20240201", rpm:"libre2-11-20240201~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grpc-devel", rpm:"grpc-devel~1.60.0~150400.8.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-grpcio", rpm:"python311-grpcio~1.60.0~150400.9.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-devel-debuginfo", rpm:"protobuf-devel-debuginfo~25.1~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-grpcio-debugsource", rpm:"python-grpcio-debugsource~1.60.0~150400.9.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"re2-debugsource-20240201", rpm:"re2-debugsource-20240201~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf25_1_0-debuginfo", rpm:"libprotobuf25_1_0-debuginfo~25.1~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abseil-cpp-debugsource", rpm:"abseil-cpp-debugsource~20230802.1~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"upb-devel", rpm:"upb-devel~1.60.0~150400.8.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2-11-debuginfo-20240201", rpm:"libre2-11-debuginfo-20240201~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgrpc++1_60-debuginfo", rpm:"libgrpc++1_60-debuginfo~1.60.0~150400.8.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgrpc++1_60", rpm:"libgrpc++1_60~1.60.0~150400.8.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grpc-debuginfo", rpm:"grpc-debuginfo~1.60.0~150400.8.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgrpc1_60-debuginfo", rpm:"libgrpc1_60-debuginfo~1.60.0~150400.8.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"re2-devel-20240201", rpm:"re2-devel-20240201~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc25_1_0-debuginfo", rpm:"libprotoc25_1_0-debuginfo~25.1~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-devel", rpm:"protobuf-devel~25.1~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc25_1_0", rpm:"libprotoc25_1_0~25.1~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0-debuginfo", rpm:"libprotobuf-lite25_1_0-debuginfo~25.1~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgrpc37", rpm:"libgrpc37~1.60.0~150400.8.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abseil-cpp-devel", rpm:"abseil-cpp-devel~20230802.1~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grpc-devel-debuginfo", rpm:"grpc-devel-debuginfo~1.60.0~150400.8.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grpc-source", rpm:"grpc-source~1.60.0~150400.8.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-abseil", rpm:"python311-abseil~1.4.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opencensus-proto-source", rpm:"opencensus-proto-source~0.3.0+git.20200721~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2-11-32bit-debuginfo-20240201", rpm:"libre2-11-32bit-debuginfo-20240201~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2-11-32bit-20240201", rpm:"libre2-11-32bit-20240201~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0-32bit", rpm:"libprotobuf-lite25_1_0-32bit~25.1~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabsl2308_0_0-32bit-debuginfo", rpm:"libabsl2308_0_0-32bit-debuginfo~20230802.1~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0-32bit-debuginfo", rpm:"libprotobuf-lite25_1_0-32bit-debuginfo~25.1~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf25_1_0-32bit-debuginfo", rpm:"libprotobuf25_1_0-32bit-debuginfo~25.1~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc25_1_0-32bit", rpm:"libprotoc25_1_0-32bit~25.1~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc25_1_0-32bit-debuginfo", rpm:"libprotoc25_1_0-32bit-debuginfo~25.1~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabsl2308_0_0-32bit", rpm:"libabsl2308_0_0-32bit~20230802.1~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf25_1_0-32bit", rpm:"libprotobuf25_1_0-32bit~25.1~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.3") {

  if(!isnull(res = isrpmvuln(pkg:"libabsl2308_0_0", rpm:"libabsl2308_0_0~20230802.1~150400.10.4.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0", rpm:"libprotobuf-lite25_1_0~25.1~150400.9.3.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0-debuginfo", rpm:"libprotobuf-lite25_1_0-debuginfo~25.1~150400.9.3.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abseil-cpp-debugsource", rpm:"abseil-cpp-debugsource~20230802.1~150400.10.4.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabsl2308_0_0-debuginfo", rpm:"libabsl2308_0_0-debuginfo~20230802.1~150400.10.4.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.4") {

  if(!isnull(res = isrpmvuln(pkg:"libabsl2308_0_0", rpm:"libabsl2308_0_0~20230802.1~150400.10.4.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0", rpm:"libprotobuf-lite25_1_0~25.1~150400.9.3.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0-debuginfo", rpm:"libprotobuf-lite25_1_0-debuginfo~25.1~150400.9.3.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abseil-cpp-debugsource", rpm:"abseil-cpp-debugsource~20230802.1~150400.10.4.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabsl2308_0_0-debuginfo", rpm:"libabsl2308_0_0-debuginfo~20230802.1~150400.10.4.1", rls:"openSUSELeapMicro5.4"))) {
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
