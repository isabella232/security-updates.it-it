---
TOCTitle: Database dei servizi directory RMS
Title: Database dei servizi directory RMS
ms:assetid: '6f6b8586-5d17-4a40-94a3-4dc738195301'
ms:contentKeyID: 18824644
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Cc747617(v=WS.10)'
---

Database dei servizi directory RMS
==================================

Nel server database viene memorizzato il database dei servizi di directory, che contiene informazioni su utenti, identificatori (ad esempio indirizzi di posta elettronica), ID di protezione (SID), appartenenza ai gruppi e identificatori alternativi. Queste informazioni vengono ottenute mediante query LDAP eseguite nel catalogo globale di Active Directory dal servizio di gestione licenze RMS. Per ulteriori informazioni su questo processo e sul suo scopo, vedere "[Cache Active Directory di RMS](https://technet.microsoft.com/c721a2eb-2fe9-4346-b426-3cc169b97265)" più avanti in questo argomento.

Al gruppo del servizio RMS sono assegnate le autorizzazione di esecuzione per le procedure presenti nel database dei servizi di directory.

Nella tabella seguente vengono elencati gli attributi di Active Directory memorizzati nelle tabelle del database dei servizi di directory.

###  

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<thead>
<tr class="header">
<th>Tabella</th>
<th>Attributo</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>GroupAliases</p></td>
<td style="border:1px solid black;"><ul>
<li>GroupName: alias del gruppo<br />
<br />
</li>
<li>GroupID: ID univoco del gruppo<br />
<br />
</li>
</ul></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>GroupIdentifiers</p></td>
<td style="border:1px solid black;"><ul>
<li>GroupDN: nome distinto del gruppo utilizzato in Active Directory<br />
<br />
</li>
<li>GroupID: ID univoco del gruppo<br />
<br />
</li>
<li>Expiration: data e ora di scadenza delle informazioni memorizzate per il gruppo<br />
<br />
</li>
</ul></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>GroupMembership</p></td>
<td style="border:1px solid black;"><ul>
<li>GroupID: ID univoco del gruppo<br />
<br />
</li>
<li>ParentID: ID univoco del gruppo a cui appartiene questo gruppo<br />
<br />
</li>
</ul></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>PrincipalAliases</p></td>
<td style="border:1px solid black;"><ul>
<li>PrincipalName: nome alias dell'identità<br />
<br />
</li>
<li>PrincipalID: ID univoco dell'identità<br />
<br />
</li>
</ul></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>PrincipalIdentifiers</p></td>
<td style="border:1px solid black;"><ul>
<li>PrincipalID: ID univoco dell'identità<br />
<br />
</li>
<li>Expiration: data e ora di scadenza delle informazioni memorizzate per l'identità<br />
<br />
</li>
</ul></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>PrincipalMembership</p></td>
<td style="border:1px solid black;"><p>Ogni riga di questa tabella include l'ID univoco di un'identità e l'ID univoco del gruppo a cui appartiene.</p>
<ul>
<li>PrincipalID: ID univoco dell'identità<br />
<br />
</li>
<li>ParentID: ID univoco di un gruppo a cui appartiene questa identità<br />
<br />
</li>
</ul></td>
</tr>
</tbody>
</table>
