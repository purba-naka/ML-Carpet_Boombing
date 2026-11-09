import pandas as pd, numpy as np, sys, json
from collections import Counter
base='dataset/csv/sesi%d_all.csv/sesi%d_all.csv'
for s in (1,2,3):
    f=base%(s,s)
    n=0; lab=Counter(); proto=Counter(); nan=0; inf=0; neg=Counter(); src=Counter(); dstsub=Counter(); tmin=None; tmax=None
    cols=None; bad_ts=0; dtypes_obj=set()
    lab_src=Counter(); lab_dstsub=Counter(); lab_proto=Counter()
    for ch in pd.read_csv(f,chunksize=500000,low_memory=False):
        if cols is None: cols=list(ch.columns)
        n+=len(ch)
        lab.update(ch['Label'].astype(str).value_counts().to_dict())
        proto.update(ch['Protocol'].value_counts().to_dict())
        num=ch.select_dtypes(include=[np.number])
        nan+=int(num.isna().sum().sum()); inf+=int(np.isinf(num).sum().sum())
        for c in ('Flow Duration','Flow Bytes/s','Flow Packets/s','Total Fwd Packet'):
            neg[c]+=int((ch[c]<0).sum())
        dtypes_obj|=set(ch.select_dtypes(include='object').columns)
        ts=pd.to_datetime(ch['Timestamp'],format='%d/%m/%Y %I:%M:%S %p',errors='coerce')
        bad_ts+=int(ts.isna().sum())
        tmin=ts.min() if tmin is None else min(tmin,ts.min()); tmax=ts.max() if tmax is None else max(tmax,ts.max())
        sub=ch['Dst IP'].str.rsplit('.',n=1).str[0]
        dstsub.update(sub.value_counts().head(20).to_dict())
        src.update(ch['Src IP'].value_counts().head(20).to_dict())
        g=ch.assign(sub=sub).groupby(['Label','sub']).size()
        for k,v in g.items(): lab_dstsub[k]+=v
        g=ch.groupby(['Label','Src IP']).size()
        for k,v in g.items(): lab_src[k]+=v
        g=ch.groupby(['Label','Protocol']).size()
        for k,v in g.items(): lab_proto[k]+=v
    print('=====sesi',s,'rows',n,'cols',len(cols))
    print('labels',dict(lab)); print('proto',dict(proto))
    print('nan',nan,'inf',inf,'neg',dict(neg),'bad_ts',bad_ts,'ts',tmin,tmax)
    print('object cols',dtypes_obj)
    print('label x dstsubnet', {k:v for k,v in lab_dstsub.items() if v>1000})
    print('label x srcIP top', sorted(lab_src.items(),key=lambda x:-x[1])[:25])
    print('label x proto', dict(lab_proto))
