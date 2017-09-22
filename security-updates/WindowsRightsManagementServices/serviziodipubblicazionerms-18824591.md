---
TOCTitle: Servizio di pubblicazione RMS
Title: Servizio di pubblicazione RMS
ms:assetid: '4c0c8fe3-695c-4b2c-a2d3-cab9b52bbb25'
ms:contentKeyID: 18824591
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Cc720267(v=WS.10)'
---

Servizio di pubblicazione RMS
=============================

Il servizio di pubblicazione, che emette le licenze di pubblicazione, viene eseguito sul server principale di RMS e sugli eventuali cluster licenze. Le licenze di pubblicazione definiscono i criteri in base a cui le licenze d'uso possono essere rilasciate.

Il file di applicazione del servizio di pubblicazione, Publish.asmx, è memorizzato nella directory virtuale Licensing di IIS.

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
