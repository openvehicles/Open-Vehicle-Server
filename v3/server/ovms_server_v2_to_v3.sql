-- OVMS Server Database Schema
--
-- V2 to V3 upgrade script

--
-- New ovms_apitokens table
--

DROP TABLE IF EXISTS `ovms_apitokens`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
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
SET character_set_client = @saved_cs_client;

--
-- Clean up before continuing
--

DELETE FROM ovms_owners WHERE deleted=1;
DELETE FROM ovms_cars WHERE owner NOT IN (SELECT owner FROM ovms_owners);
DELETE FROM ovms_cars WHERE deleted=1;

--
-- Add 'owner' to ovms_cars, alongside 'vehicleid' to make vehicle IDs unqiue per owner (not globally)
--

ALTER TABLE ovms_cars DROP primary key, ADD primary key (`owner`,`vehicleid`);

--
-- Add 'owner' to ovms_carmessages, alongside 'vehicleid' to make vehicle IDs unqiue per owner (not globally)
--

ALTER TABLE ovms_carmessages ADD COLUMN `owner` int(10) unsigned NOT NULL default '0' FIRST,
  DROP PRIMARY KEY,
  ADD PRIMARY KEY (`owner`,`vehicleid`,`m_code`);

DELETE FROM ovms_carmessages WHERE vehicleid NOT IN (SELECT vehicleid FROM ovms_cars);

UPDATE ovms_carmessages
  SET owner=(SELECT owner FROM ovms_cars WHERE ovms_cars.vehicleid=ovms_carmessages.vehicleid);

--
-- Add 'owner' to ovms_historicalmessages, alongside 'vehicleid' to make vehicle IDs unqiue per owner (not globally)
--

ALTER TABLE ovms_historicalmessages ADD COLUMN `owner` int(10) unsigned NOT NULL default '0' FIRST,
  DROP PRIMARY KEY,
  ADD PRIMARY KEY (`owner`,`vehicleid`,`h_recordtype`,`h_recordnumber`,`h_timestamp`);

DELETE FROM ovms_historicalmessages WHERE vehicleid NOT IN (SELECT vehicleid FROM ovms_cars);

UPDATE ovms_historicalmessages
  SET owner=(SELECT owner FROM ovms_cars WHERE ovms_cars.vehicleid=ovms_historicalmessages.vehicleid);

--
-- Add 'owner' to ovms_notifies, alongside 'vehicleid' to make vehicle IDs unqiue per owner (not globally)
--

ALTER TABLE ovms_notifies ADD COLUMN `owner` int(10) unsigned NOT NULL default '0' FIRST,
  DROP PRIMARY KEY,
  ADD PRIMARY KEY (`owner`,`vehicleid`,`appid`);

DELETE FROM ovms_notifies WHERE vehicleid NOT IN (SELECT vehicleid FROM ovms_cars);

UPDATE ovms_notifies
  SET owner=(SELECT owner FROM ovms_cars WHERE ovms_cars.vehicleid=ovms_notifies.vehicleid);

--
-- All done
--
