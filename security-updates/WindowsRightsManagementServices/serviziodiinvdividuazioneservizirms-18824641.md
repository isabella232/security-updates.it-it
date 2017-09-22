---
TOCTitle: Servizio di invdividuazione servizi RMS
Title: Servizio di invdividuazione servizi RMS
ms:assetid: '6f410cc9-5d5b-4df3-bf4f-7b13811eb52f'
ms:contentKeyID: 18824641
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Cc747548(v=WS.10)'
---

Servizio di invdividuazione servizi RMS
=======================================

Il servizio di individuazione dei servizi viene eseguito sia sul cluster principale di RMS che sui cluster licenze. Il servizio di individuazione servizi fornisce l'URL di connessione dei servizi del cluster ad Active Directory perché possa essere individuato dai client abilitati per RMS.

Il file di applicazione del servizio di rilevamento dei servizi, ServiceLocator.asmx, è memorizzato nelle directory virtuali Certification e Licensing di IIS.

L'elenco di controllo di accesso predefinito su questo servizio è illustrato nella seguente tabella:

###  

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<thead>
<tr class="header">
<th>Utente o gruppo</th>
<th>Autorizzazione predefinita</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Administrators</p></td>
<td style="border:1px solid black;"><p>Controllo completo</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Gruppo di servizi RMS</p></td>
<td style="border:1px solid black;"><p>Lettura e Esecuzione</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>SISTEMA</p></td>
<td style="border:1px solid black;"><p>Controllo completo</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Utenti</p></td>
<td style="border:1px solid black;"><p>Lettura e Esecuzione</p></td>
</tr>  
</tbody>  
</table>
