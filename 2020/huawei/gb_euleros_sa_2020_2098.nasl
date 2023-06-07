# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.2098");
  script_cve_id("CVE-2017-6827", "CVE-2017-6828", "CVE-2017-6829", "CVE-2017-6830", "CVE-2017-6831", "CVE-2017-6832", "CVE-2017-6833", "CVE-2017-6834", "CVE-2017-6835", "CVE-2017-6836", "CVE-2017-6837", "CVE-2017-6838", "CVE-2017-6839", "CVE-2018-13440", "CVE-2018-17095");
  script_tag(name:"creation_date", value:"2020-09-29 13:45:24 +0000 (Tue, 29 Sep 2020)");
  script_version("2021-07-22T02:24:02+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-09 15:08:00 +0000 (Tue, 09 Feb 2021)");

  script_name("Huawei EulerOS: Security Advisory for audiofile (EulerOS-SA-2020-2098)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-2098");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2098");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'audiofile' package(s) announced via the EulerOS-SA-2020-2098 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The audiofile Audio File Library 0.3.6 has a NULL pointer dereference bug in ModuleState::setup in modules/ModuleState.cpp, which allows an attacker to cause a denial of service via a crafted caf file, as demonstrated by sfconvert.(CVE-2018-13440)

An issue has been discovered in mpruett Audio File Library (aka audiofile) 0.3.6. A heap-based buffer overflow in Expand3To4Module::run has occurred when running sfconvert.(CVE-2018-17095)

Heap-based buffer overflow in the MSADPCM::initializeCoefficients function in MSADPCM.cpp in audiofile (aka libaudiofile and Audio File Library) 0.3.6 allows remote attackers to have unspecified impact via a crafted audio file.(CVE-2017-6827)

Heap-based buffer overflow in the readValue function in FileHandle.cpp in audiofile (aka libaudiofile and Audio File Library) 0.3.6 allows remote attackers to have unspecified impact via a crafted WAV file.(CVE-2017-6828)

The decodeSample function in IMA.cpp in Audio File Library (aka audiofile) 0.3.6 allows remote attackers to cause a denial of service (crash) via a crafted file.(CVE-2017-6829)

Heap-based buffer overflow in the alaw2linear_buf function in G711.cpp in Audio File Library (aka audiofile) 0.3.6 allows remote attackers to cause a denial of service (crash) via a crafted file.(CVE-2017-6830)

Heap-based buffer overflow in the decodeBlockWAVE function in IMA.cpp in Audio File Library (aka audiofile) 0.3.6 allows remote attackers to cause a denial of service (crash) via a crafted file.(CVE-2017-6831)

Heap-based buffer overflow in the decodeBlock in MSADPCM.cpp in Audio File Library (aka audiofile) 0.3.6 allows remote attackers to cause a denial of service (crash) via a crafted file.(CVE-2017-6832)

The runPull function in libaudiofile/modules/BlockCodec.cpp in Audio File Library (aka audiofile) 0.3.6 allows remote attackers to cause a denial of service (divide-by-zero error and crash) via a crafted file.(CVE-2017-6833)

Heap-based buffer overflow in the ulaw2linear_buf function in G711.cpp in Audio File Library (aka audiofile) 0.3.6 allows remote attackers to cause a denial of service (crash) via a crafted file.(CVE-2017-6834)

The reset1 function in libaudiofile/modules/BlockCodec.cpp in Audio File Library (aka audiofile) 0.3.6 allows remote attackers to cause a denial of service (divide-by-zero error and crash) via a crafted file.(CVE-2017-6835)

Heap-based buffer overflow in the Expand3To4Module::run function in libaudiofile/modules/SimpleModule.h in Audio File Library (aka audiofile) 0.3.6 allows remote attackers to cause a denial of service (crash) via a crafted file.(CVE-2017-6836)

WAVE.cpp in Audio File Library (aka audiofile) 0.3.6 allows remote attackers to cause a denial of service (crash) via vectors related to a large number of coefficients.(CVE-2017-6837)

Integer overflow in sfcommands/sfconvert.c in Audio File Library (aka audiofile) 0.3.6 allows remote attackers to cause a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'audiofile' package(s) on Huawei EulerOS V2.0SP3.");

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

if(release == "EULEROS-2.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"audiofile", rpm:"audiofile~0.3.6~4.h2", rls:"EULEROS-2.0SP3"))) {
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
