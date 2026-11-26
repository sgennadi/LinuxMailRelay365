namespace LinuxMailRelay365;

// Guidance, not authorization. Only observations bound to the current source
// map and exact row may contribute. A completed screen is never delivery proof.
internal sealed record MultiMailboxWizardProgress(int SuggestedStep, int Count, int Certificates,
    int Cloud, int Auth, string Route, bool InventoryVerified)
{
    internal const int LastStep = 5;
    internal static int Adjacent(int step, bool forward) =>
        Math.Clamp(step + (forward ? 1 : -1),0,LastStep);

    internal static bool Fresh(DateTimeOffset sampled, DateTimeOffset now) =>
        sampled <= now && now-sampled <= TimeSpan.FromMinutes(10);

    internal static bool SameInventory(MultiMailboxIdentityInventory left, MultiMailboxIdentityInventory right) =>
        left.Source.Status==right.Source.Status && left.Source.Sha256==right.Source.Sha256 &&
        left.Runtime.Status==right.Runtime.Status && left.Runtime.Sha256==right.Runtime.Sha256 &&
        left.Relation==right.Relation && left.InstalledBinding==right.InstalledBinding &&
        left.Source.Rows.SequenceEqual(right.Source.Rows) && left.Runtime.Rows.SequenceEqual(right.Runtime.Rows);

    internal static MultiMailboxWizardProgress Evaluate(MultiMailboxIdentityInventory inventory, bool valid,
        bool uncertain, bool prepared, IReadOnlyDictionary<MultiMailboxCloudSelection,MultiMailboxCloudObservation> cloud,
        IReadOnlyDictionary<MultiMailboxCloudSelection,(MultiMailboxSmtpAuthReceipt Receipt,DateTimeOffset Sampled)> auth,
        DateTimeOffset now)
    {
        bool verified=valid && !uncertain && inventory.Source.Status is "ok" or "absent" &&
            inventory.Runtime.Status is "ok" or "absent";
        if (!verified) return new(0,0,0,0,0,"review_required",false);
        var rows=inventory.Source.Rows;
        int certs=0,cloudCount=0,authCount=0;
        foreach(var row in rows)
        {
            if(row.Status!="public_certificate_read") continue;
            var selection=MultiMailboxCloudSelection.Capture(inventory,"source",row);
            if(selection is null) continue;
            certs++;
            if(cloud.TryGetValue(selection,out var observed) && observed.Selection==selection &&
                Fresh(observed.SampledAt,now) &&
                observed.GraphStatus(now)=="matches_graph_credential_dates" &&
                observed.Cloud.MailboxAudit?.ScopedConfigurationObserved==true) cloudCount++;
            if(auth.TryGetValue(selection,out var sample) && Fresh(sample.Sampled,now) &&
                sample.Receipt.Authenticated) authCount++;
        }
        string route=inventory.InstalledBinding=="not_installed" && inventory.Runtime.Status=="absent" ?
            "not_installed" : inventory.InstalledBinding=="matches_marker" && inventory.Relation=="same" ?
            "map_matches_marker" : "review_required";
        int suggested=rows.Length==0 ? (prepared?1:0) : certs!=rows.Length ? 1 :
            cloudCount!=rows.Length ? 2 : authCount!=rows.Length ? 3 :
            route=="map_matches_marker" ? 5 : 4;
        return new(suggested,rows.Length,certs,cloudCount,authCount,route,true);
    }

    internal static bool SelfTest()
    {
        var now=DateTimeOffset.UtcNow;
        var absent=new MultiMailboxIdentityMap("absent","",[]);
        var empty=new MultiMailboxIdentityInventory(absent,absent,"neither","not_installed");
        var cloud=new Dictionary<MultiMailboxCloudSelection,MultiMailboxCloudObservation>();
        var auth=new Dictionary<MultiMailboxCloudSelection,(MultiMailboxSmtpAuthReceipt Receipt,DateTimeOffset Sampled)>();
        MultiMailboxWizardProgress Check(MultiMailboxIdentityInventory i,bool valid=true,bool uncertain=false,bool prepared=false)
            =>Evaluate(i,valid,uncertain,prepared,cloud,auth,now);
        if(Check(empty).SuggestedStep!=0 || Check(empty,prepared:true).SuggestedStep!=1 ||
            Check(empty,uncertain:true).InventoryVerified || Adjacent(0,false)!=0 || Adjacent(5,true)!=5) return false;
        Guid tenant=Guid.NewGuid(),client=Guid.NewGuid(),sp=Guid.NewGuid();
        var row=new MultiMailboxIdentityRow("alice","alice@example.org","alice@example.org",tenant,client,
            new string('a',64),new string('b',64),"software","public_certificate_read");
        var map=new MultiMailboxIdentityMap("ok",new string('c',64),[row]);
        var inventory=new MultiMailboxIdentityInventory(map,absent,"source_only","not_installed");
        var key=MultiMailboxCloudSelection.Capture(inventory,"source",row)!;
        if(Check(inventory).SuggestedStep!=2) return false;
        var audit=new CloudSmtpMailboxAudit(row.Mailbox,sp,"verified","enabled","inherit","enabled","verified","in_scope");
        var observed=new CloudObjectsInventory(tenant,client,"found",Guid.NewGuid(),"fixture","found",sp,
            [new(Guid.NewGuid(),"fixture","AsymmetricX509Cert","Verify",now.AddDays(-1),now.AddDays(1),row.CertificateSha)],
            [],[],[],audit);
        cloud[key]=MultiMailboxCloudObservation.Create(key,observed,now);
        if(Check(inventory).SuggestedStep!=3) return false;
        auth[key]=(new("authenticated"),now);
        if(Check(inventory).SuggestedStep!=4 || Check(inventory).Auth!=1) return false;
        var installed=inventory with { Runtime=map,Relation="same",InstalledBinding="matches_marker" };
        if(Check(installed).SuggestedStep!=5 || SameInventory(inventory,installed) ||
            !SameInventory(inventory,inventory with {Source=map with {Rows=[row]}})) return false;
        var changed=inventory with { Source=map with {Sha256=new string('d',64)} };
        if(Check(changed).Cloud!=0 || Check(changed).Auth!=0) return false;
        auth[key]=(new("authenticated"),now.AddMinutes(-11));
        if(Check(inventory).SuggestedStep!=3 || Fresh(now.AddSeconds(1),now)) return false;
        cloud[key]=MultiMailboxCloudObservation.Create(key,observed,now.AddMinutes(-11));
        return Check(inventory).SuggestedStep==2 && !Check(inventory,valid:false).InventoryVerified;
    }
}
