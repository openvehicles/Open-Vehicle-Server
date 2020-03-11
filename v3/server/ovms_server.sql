-- MySQL dump 10.13  Distrib 5.7.28, for Linux (x86_64)
--
-- Host: localhost    Database: openvehicles
-- ------------------------------------------------------
-- Server version	5.7.28

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `ovms_apitokens`
--

DROP TABLE IF EXISTS `ovms_apitokens`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ovms_apitokens` (
  `owner` int(10) unsigned NOT NULL,
  `token` varchar(64) NOT NULL,
  `application` varchar(32) NOT NULL DEFAULT '',
  `purpose` varchar(80) NOT NULL DEFAULT '',
  `permit` varchar(255) NOT NULL DEFAULT 'none',
  `created` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `refreshed` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastused` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`owner`,`token`),
  KEY `token` (`token`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COMMENT='OVMS: API tokens';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ovms_autoprovision`
--

DROP TABLE IF EXISTS `ovms_autoprovision`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ovms_autoprovision` (
  `ap_key` varchar(64) NOT NULL DEFAULT '' COMMENT 'Unique Auto-Provisioning Key',
  `ap_stoken` varchar(32) NOT NULL DEFAULT '',
  `ap_sdigest` varchar(32) NOT NULL DEFAULT '',
  `ap_msg` varchar(4096) NOT NULL DEFAULT '',
  `deleted` tinyint(1) NOT NULL DEFAULT '0',
  `changed` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `owner` int(10) unsigned NOT NULL DEFAULT '0',
  `v_lastused` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`ap_key`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COMMENT='OVMS: Auto-Provisioning Records';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ovms_carmessages`
--

DROP TABLE IF EXISTS `ovms_carmessages`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ovms_carmessages` (
  `owner` int(10) unsigned NOT NULL DEFAULT '0',
  `vehicleid` varchar(32) NOT NULL DEFAULT '' COMMENT 'Unique vehicle ID',
  `m_code` char(1) NOT NULL DEFAULT '',
  `m_valid` tinyint(1) NOT NULL DEFAULT '1',
  `m_msgtime` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `m_paranoid` tinyint(1) NOT NULL DEFAULT '0',
  `m_ptoken` varchar(32) NOT NULL DEFAULT '',
  `m_msg` varchar(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`owner`,`vehicleid`,`m_code`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COMMENT='OVMS: Stores vehicle messages';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ovms_cars`
--

DROP TABLE IF EXISTS `ovms_cars`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ovms_cars` (
  `vehicleid` varchar(32) NOT NULL DEFAULT '' COMMENT 'Unique vehicle ID',
  `vehiclename` varchar(64) NOT NULL DEFAULT '',
  `owner` int(10) unsigned NOT NULL DEFAULT '0' COMMENT 'Owner user ID.',
  `telephone` varchar(48) NOT NULL DEFAULT '',
  `carpass` varchar(255) NOT NULL DEFAULT '' COMMENT 'Car password',
  `userpass` varchar(255) NOT NULL DEFAULT '' COMMENT 'User password (optional)',
  `cryptscheme` varchar(1) NOT NULL DEFAULT '0',
  `v_ptoken` varchar(32) NOT NULL DEFAULT '',
  `v_server` varchar(32) NOT NULL DEFAULT '*',
  `v_type` varchar(10) NOT NULL DEFAULT 'CAR',
  `deleted` tinyint(1) NOT NULL DEFAULT '0',
  `changed` datetime NOT NULL DEFAULT '1900-01-01 00:00:00',
  `v_lastupdate` datetime NOT NULL DEFAULT '1900-01-01 00:00:00',
  `couponcode` varchar(32) NOT NULL DEFAULT '',
  PRIMARY KEY (`owner`,`vehicleid`),
  KEY `owner` (`owner`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COMMENT='OVMS: Stores vehicle current data';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ovms_historicalmessages`
--

DROP TABLE IF EXISTS `ovms_historicalmessages`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ovms_historicalmessages` (
  `owner` int(10) unsigned NOT NULL DEFAULT '0',
  `vehicleid` varchar(32) NOT NULL DEFAULT '' COMMENT 'Unique vehicle ID',
  `h_timestamp` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `h_recordtype` varchar(32) NOT NULL DEFAULT '',
  `h_recordnumber` int(5) NOT NULL DEFAULT '0',
  `h_data` text NOT NULL,
  `h_expires` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`owner`,`vehicleid`,`h_recordtype`,`h_recordnumber`,`h_timestamp`),
  KEY `h_expires` (`h_expires`),
  KEY `h_recordtype` (`h_recordtype`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COMMENT='OVMS: Stores historical data records';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ovms_notifies`
--

DROP TABLE IF EXISTS `ovms_notifies`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ovms_notifies` (
  `owner` int(10) unsigned NOT NULL DEFAULT '0',
  `vehicleid` varchar(32) NOT NULL DEFAULT '' COMMENT 'Unique vehicle ID',
  `appid` varchar(128) NOT NULL DEFAULT '' COMMENT 'Unique App ID',
  `pushtype` varchar(16) NOT NULL DEFAULT '',
  `pushkeytype` varchar(16) NOT NULL DEFAULT '',
  `pushkeyvalue` varchar(256) NOT NULL DEFAULT '',
  `lastupdated` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `active` tinyint(1) NOT NULL DEFAULT '1',
  PRIMARY KEY (`owner`,`vehicleid`,`appid`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COMMENT='OVMS: Stores app notification configs';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ovms_owners`
--

DROP TABLE IF EXISTS `ovms_owners`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ovms_owners` (
  `owner` int(10) unsigned NOT NULL,
  `name` varchar(60) NOT NULL DEFAULT '',
  `mail` varchar(254) NOT NULL DEFAULT '',
  `pass` varchar(128) NOT NULL DEFAULT '',
  `status` tinyint(4) NOT NULL DEFAULT '0',
  `deleted` tinyint(1) NOT NULL DEFAULT '0',
  `changed` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`owner`),
  KEY `name` (`name`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COMMENT='OVMS: Stores vehicle owners';
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2020-03-11 14:08:21
