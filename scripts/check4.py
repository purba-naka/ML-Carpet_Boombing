import pandas as pd, numpy as np, glob
pd.set_option('display.width',250); pd.set_option('display.max_columns',40); pd.set_option('display.max_rows',200)
log=pd.read_csv('dataset/Attack_log-20261109T113913Z-1-001/Attack_log/attack_log.csv').set_index('run_id')
cols=['Src IP','Dst IP','Protocol','Timestamp','Flow Duration','Total Fwd Packet','Total Length of Fwd Packet','Dst Port','Src Port','Flow ID']
df=pd.concat([pd.read_csv('dataset/csv/sesi%d_all.csv/sesi%d_all.csv'%(s,s),usecols=cols) for s in (1,2,3)],ignore_index=True)
df['t']=pd.to_datetime(df['Timestamp'],format='%d/%m/%Y %I:%M:%S %p')
df['ep']=(df['t']-pd.Timestamp('1970-01-01')).dt.total_seconds().astype('int64')
print('dup Flow ID+ts:',df.duplicated(['Flow ID','Timestamp']).sum(),' dup Flow ID',df.duplicated(['Flow ID']).sum())
print('Dst Port top',df['Dst Port'].value_counts().head(8).to_dict())
for rid in ['C1','C3','C2','C6','C7','F1','F3']:
    r=log.loc[rid]; w=df[(df.ep>=r.start_ts)&(df.ep<=r.end_ts)]
    if r.n_src=='1':
        a=w[w['Src IP']=='192.168.1.65']
    else:
        a=w[~w['Src IP'].str.startswith('198.51.100.')&(w['Src IP']!='8.6.0.1')]
    print('\n==',rid,r.scenario,'cfgdst',r.dst,'nsrc',r.n_src,'attflows',len(a),'uDst',a['Dst IP'].nunique(),'uSrc',a['Src IP'].nunique(),'dport',a['Dst Port'].value_counts().head(3).to_dict(),'sport uniq',a['Src Port'].nunique())
    print(' dst sample',sorted(a['Dst IP'].unique(),key=lambda x:int(x.split('.')[-1]))[:70] if a['Dst IP'].nunique()<=70 else ('many',a['Dst IP'].value_counts().head(5).to_dict()))
    print(' pktlen/flow fwd pkts',a['Total Fwd Packet'].describe()[['mean','max']].to_dict(),'bytes/flow mean',a['Total Length of Fwd Packet'].mean())
    print(' src sample',a['Src IP'].value_counts().head(4).to_dict())
# unlogged heavy windows
for a,b in (('2026-11-02 09:48','2026-11-02 09:58'),('2026-11-02 10:14','2026-11-02 10:24')):
    w=df[(df.t>=a)&(df.t<=b)&(df['Src IP']=='192.168.1.65')]
    print('\nUNLOGGED',a,len(w),'uDst',w['Dst IP'].nunique(),w.t.min(),w.t.max(),'dport',w['Dst Port'].value_counts().head(3).to_dict(),'pkt/flow',w['Total Fwd Packet'].mean())
    print(w.groupby(w.t.dt.floor('min')).size().to_dict())
# attacker background
bg=df[(df['Src IP']=='192.168.1.65')&((df.t>'2026-11-02 11:00')&(df.t<'2026-11-02 12:20'))]
print('\nattacker background',len(bg),bg['Dst IP'].value_counts().head(5).to_dict(),bg['Dst Port'].value_counts().head(5).to_dict(),bg.Protocol.value_counts().to_dict())
# benign servers
ben=df[df['Src IP'].str.startswith('198.51.100.')]
print('\nflows with src in LAN subnet',len(ben),'top src',ben['Src IP'].value_counts().head(5).to_dict())
print('Src 198.51.100.199 dst',df[df['Src IP']=='198.51.100.199']['Dst IP'].value_counts().head(5).to_dict(),df[df['Src IP']=='198.51.100.199']['Dst Port'].value_counts().head(5).to_dict())
print('Dst .10 top src',df[df['Dst IP']=='198.51.100.10']['Src IP'].value_counts().head(5).to_dict())
print('Dst .10 dport',df[df['Dst IP']=='198.51.100.10']['Dst Port'].value_counts().head(5).to_dict())
# run overlaps / adjacency
L=log.sort_values('start_ts'); print('\ngaps between runs (s):',(L.start_ts.shift(-1)-L.end_ts).dropna().astype(int).tolist())
# old dataset
print('\n=== old 20261016 flows')
for f in sorted(glob.glob('flows_csv*/flows_csv/*.csv')):
    d=pd.read_csv(f,low_memory=False); print(f.split('/')[-1],len(d),d['Label'].unique()[:3],d['Timestamp'].iloc[0] if len(d) else '',d['Src IP'].nunique(),d['Dst IP'].nunique(),d.Protocol.value_counts().to_dict())
