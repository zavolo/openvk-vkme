CREATE TABLE IF NOT EXISTS `im_exchange_tokens` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `token` varchar(128) NOT NULL,
  `user` bigint(20) NOT NULL,
  `created` bigint(20) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `token_unique` (`token`),
  KEY `user_idx` (`user`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
