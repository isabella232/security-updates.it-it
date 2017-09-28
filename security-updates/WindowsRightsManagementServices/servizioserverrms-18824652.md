---
TOCTitle: Servizio server RMS
Title: Servizio server RMS
ms:assetid: '772d0a89-c9fb-4430-9434-38cd5add1e86'
ms:contentKeyID: 18824652
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Cc747566(v=WS.10)'
---

Servizio server RMS
===================

Il servizio server viene eseguito solo sul cluster principale di RMS. Nel Servizio server vengono esposte le richieste fatte dai client mediante la pubblicazione in linea per ottenere un certificato concessore di licenze server.

Il file di applicazione del servizio Server, Server.asmx, è memorizzato nella directory virtuale Certification di IIS.

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
