SET default_storage_engine=InnoDB;

DROP TABLE IF EXISTS `FUNCTIONS`;
DROP TABLE IF EXISTS `CLASSES`;
DROP TABLE IF EXISTS `FILES`;
DROP TABLE IF EXISTS `SECURITY_ADVISORIES`;
DROP TABLE IF EXISTS `PATCHES`;
DROP TABLE IF EXISTS `REPOSITORIES_SAMPLE`;
DROP TABLE IF EXISTS `CODE_HEADER`;
DROP TABLE IF EXISTS `VULNERABILITIES`;
DROP TABLE IF EXISTS `MODULE_INFO`;

CREATE TABLE IF NOT EXISTS `MODULE_INFO` (
	SEQUENCE INT,
	R_ID INT,
	PATH_START CHAR(150),
	MODULE_NAME CHAR(60)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `CLASSES` (
	ID_Class BIGINT,
	P_ID CHAR(255), 
	Visibility CHAR(10), 
	Complement CHAR(24),  -- AbstractStructTemplate
	NameClass VARCHAR(110), 
	ID_File BIGINT, 
	FilePath VARCHAR(150),  -- new
	Patched BOOLEAN,
	Occurrence CHAR(7),
	R_ID TINYINT,
	AltAvgLineBlank INT,
	AltAvgLineCode INT,
	AltAvgLineComment INT,
	AltCountLineBlank INT,
	AltCountLineCode INT,
	AltCountLineComment INT,
	AvgCyclomatic INT,
	AvgCyclomaticModified INT,
	AvgCyclomaticStrict INT,
	AvgEssential INT,
	AvgLine INT,
	AvgLineBlank INT,
	AvgLineCode INT,
	AvgLineComment INT,
	CountClassBase INT,
	CountClassCoupled INT,
	CountClassDerived INT,
	CountDeclClassMethod INT,
	CountDeclClassVariable INT,
	CountDeclInstanceMethod INT,
	CountDeclInstanceVariable INT,
	CountDeclInstanceVariablePrivate INT,
	CountDeclInstanceVariableProtected INT,
	CountDeclInstanceVariablePublic INT,
	CountDeclMethod INT,
	CountDeclMethodAll INT,
	CountDeclMethodConst INT,
	CountDeclMethodFriend INT,
	CountDeclMethodPrivate INT,
	CountDeclMethodProtected INT,
	CountDeclMethodPublic INT,
	CountLine INT,
	CountLineBlank INT,
	CountLineCode INT,
	CountLineCodeDecl INT,
	CountLineCodeExe INT,
	CountLineComment INT,
	CountLineInactive INT,
	CountLinePreprocessor INT,	
	CountStmt INT,
	CountStmtDecl INT,
	CountStmtEmpty INT,
	CountStmtExe INT,	
	MaxCyclomatic INT,
	MaxCyclomaticModified INT,
	MaxCyclomaticStrict INT,
	MaxEssential INT,
	MaxInheritanceTree INT,
	MaxNesting INT,
	PercentLackOfCohesion INT,
	RatioCommentToCode FLOAT,
	SumCyclomatic INT,
	SumCyclomaticModified INT,
	SumCyclomaticStrict INT,
	SumEssential INT
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
	
	
DROP TABLE IF EXISTS `FUNCTIONS`;
CREATE TABLE IF NOT EXISTS `FUNCTIONS` (
	ID_Function BIGINT, 
	P_ID 		CHAR(255), 
	Visibility 	CHAR(10), 
	Complement 	CHAR(18), -- ExplicitTemplate
	NameMethod VARCHAR(350), 
	ID_Class BIGINT, 
	ID_File BIGINT, 
	FilePath VARCHAR(150),  -- new
	Patched BOOLEAN, -- moved
	Occurrence CHAR(7), -- moved
	R_ID TINYINT,    -- moved
	AltCountLineBlank INT,
	AltCountLineCode INT,
	AltCountLineComment INT,
	CountInput INT,
	CountLine INT,
	CountLineBlank INT,
	CountLineCode INT,
	CountLineCodeDecl INT,
	CountLineCodeExe INT,
	CountLineComment INT,
	CountLineInactive INT,
	CountLinePreprocessor INT,
	CountOutput INT,
	CountPath INT,
	CountSemicolon INT,
	CountStmt INT,
	CountStmtDecl INT,
	CountStmtEmpty INT,
	CountStmtExe INT,
	Cyclomatic INT,
	CyclomaticModified INT,
	CyclomaticStrict INT,
	Essential INT,
	Knots INT,
	MaxEssentialKnots INT,
	MaxNesting INT,
	MinEssentialKnots INT,
	RatioCommentToCode FLOAT
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

DROP TABLE IF EXISTS `FILES`;
CREATE TABLE IF NOT EXISTS `FILES` (
	ID_File BIGINT, 
	P_ID CHAR(255), 
	FilePath VARCHAR(150), 
	Patched BOOLEAN,
	Occurrence CHAR(7),
	R_ID TINYINT,
	AltAvgLineBlank INT,
	AltAvgLineCode INT,
	AltAvgLineComment INT,
	AltCountLineBlank INT,
	AltCountLineCode INT,
	AltCountLineComment INT,
	AvgCyclomatic INT,
	AvgCyclomaticModified INT,
	AvgCyclomaticStrict INT,
	AvgEssential INT,
	AvgLine INT,
	AvgLineBlank INT,
	AvgLineCode INT,
	AvgLineComment INT,
	CountDeclClass INT,
	CountDeclFunction INT,
	CountLine INT,
	CountLineBlank INT,
	CountLineCode INT,
	CountLineCodeDecl INT,
	CountLineCodeExe INT,
	CountLineComment INT,
	CountLineInactive INT,
	CountLinePreprocessor INT,
	CountSemicolon INT,
	CountStmt INT,
	CountStmtDecl INT,
	CountStmtEmpty INT,
	CountStmtExe INT,
	MaxCyclomatic INT,
	MaxCyclomaticModified INT,
	MaxCyclomaticStrict INT,
	MaxEssential INT,
	MaxNesting INT,
	RatioCommentToCode FLOAT,
	SumCyclomatic INT,
	SumCyclomaticModified INT,
	SumCyclomaticStrict INT,
	SumEssential INT
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


DROP TABLE IF EXISTS `SECURITY_ADVISORIES`;
CREATE TABLE `SECURITY_ADVISORIES` (
  `ID_ADVISORIES` varchar(20) NOT NULL,
  `TITLE` text,
  `DESCRIPTION` text,
  `M_IMPACT` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`ID_ADVISORIES`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

DROP TABLE IF EXISTS `PATCHES`;
CREATE TABLE `PATCHES` (
  `P_ID` varchar(10) NOT NULL,
  `P_URL` varchar(250) NOT NULL,
  `V_ID` varchar(30) DEFAULT NULL,
  `R_ID` TINYINT NOT NULL,
  `P_COMMIT` varchar(200),
  `ERROR_SIMILARITY` varchar(30) NOT NULL,
  `SITUATION` tinyint(4),
  `RELEASES` varchar(80) NOT NULL,
  `DATE` DATETIME DEFAULT NULL,
  PRIMARY KEY (`P_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

DROP TABLE IF EXISTS `REPOSITORIES_SAMPLE`;
CREATE TABLE `REPOSITORIES_SAMPLE` (
  `R_ID` TINYINT NOT NULL AUTO_INCREMENT,
  `R_LINK` varchar(100) NOT NULL,
  `R_TYPE` varchar(50) NOT NULL,
  `PROJECT` varchar(45) NOT NULL,
  `R_FOLDER` varchar(50) DEFAULT NULL,
  `R_INFO` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`R_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

DROP TABLE IF EXISTS `CODE_HEADER`;
CREATE TABLE `CODE_HEADER` (
  `P_ID` varchar(10) NOT NULL,
  `V_FILE` varchar(200) DEFAULT NULL,
  `V_METHOD_UNDERSTAND` varchar(200) DEFAULT NULL,
  `V_METHOD_DIFF` varchar(200) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

DROP TABLE IF EXISTS `VULNERABILITIES`;
CREATE TABLE `VULNERABILITIES` (
  `V_ID` varchar(30) NOT NULL,
  `CVE` varchar(45) DEFAULT NULL,
  `ID_ADVISORIES` varchar(45) DEFAULT NULL,
  `V_CLASSIFICATION` VARCHAR(500),
  `V_IMPACT` varchar(75) DEFAULT NULL,
  `VULNERABILITY_URL` varchar(100) DEFAULT NULL,
  `PRODUCTS` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`V_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

DROP TABLE IF EXISTS `EXTRA_TIME_FILES`;
CREATE TABLE `EXTRA_TIME_FILES` (
	ID_File BIGINT, 
	P_ID CHAR(10)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

DROP TABLE IF EXISTS `EXTRA_TIME_FUNCTIONS`;
CREATE TABLE `EXTRA_TIME_FUNCTIONS` (
	ID_Functions BIGINT, 
	P_ID CHAR(10)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

DROP TABLE IF EXISTS `EXTRA_TIME_CLASS`;
CREATE TABLE `EXTRA_TIME_CLASS` (
	ID_Class BIGINT, 
	P_ID CHAR(10)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
