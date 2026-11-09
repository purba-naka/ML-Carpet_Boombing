import pandas as pd, numpy as np, datetime as dt
log=pd.read_csv('dataset/Attack_log-20261109T113913Z-1-001/Attack_log/attack_log.csv')
cols=['Src IP','Dst IP','Protocol','Timestamp','Flow Duration','Total Fwd Packet','Total Bwd packets','Total Length of Fwd Packet']
dfs=[]
for s in (1,2,3):
    d=pd.read_csv('dataset/csv/sesi%d_all.csv/sesi%d_all.csv'%(s,s),usecols=cols)
    d['sesi']=s; dfs.append(d)
df=pd.concat(dfs,ignore_index=True)
df['t']=pd.to_datetime(df['Timestamp'],format='%d/%m/%Y %I:%M:%S %p')
df['ep']=(df['t']-pd.Timestamp('1970-01-01')).dt.total_seconds().astype('int64')
print('total',len(df))
# coverage gaps (per-minute flow counts)
mins=df.groupby(df['t'].dt.floor('min')).size()
full=pd.date_range(mins.index.min(),mins.index.max(),freq='min')
miss=full.difference(mins.index)
print('minutes covered',len(mins),'of',len(full),'missing',len(miss))
if len(miss):
    s=pd.Series(miss); grp=(s.diff()!=pd.Timedelta('1min')).cumsum()
    for g,x in s.groupby(grp): print('  gap',x.iloc[0],'->',x.iloc[-1],len(x),'min')
att='192.168.1.65'
df['is_att']=df['Src IP']==att
df['run']='none'
for _,r in log.iterrows():
    m=(df.ep>=r.start_ts)&(df.ep<=r.end_ts)
    df.loc[m,'run']=r.run_id
print('\nflows from attacker outside any window:', ((df.run=='none')&df.is_att).sum(), 'of', df.is_att.sum())
print('flows in windows from non-attacker:', ((df.run!='none')&~df.is_att).sum())
rows=[]
for _,r in log.iterrows():
    w=df[(df.run==r.run_id)]
    a=w[w.is_att]; o=w[~w.is_att]
    rows.append(dict(run=r.run_id,sc=r.scenario,dst_cfg=r.dst,pay=r.payload,nsrc=r.n_src,intv=r.interval_us,dur=r.end_ts-r.start_ts,
        att_flows=len(a),att_uniqDst=a['Dst IP'].nunique(),att_uniqSrcPort=0,att_pkts=int(a['Total Fwd Packet'].sum()),
        att_proto=dict(a.Protocol.value_counts()),other_flows=len(o),other_src=o['Src IP'].nunique(),
        srcs=a['Src IP'].nunique(), exp_pkts=int((r.end_ts-r.start_ts)*1e6/r.interval_us)))
R=pd.DataFrame(rows).drop(columns='att_uniqSrcPort')
pd.set_option('display.width',250); pd.set_option('display.max_columns',30)
print(R.to_string())
# per-sesi: which windows lie in which sesi
print(df.groupby('sesi')['t'].agg(['min','max']))
# benign: non-attacker flows outside windows
b=df[(~df.is_att)]
print('\nnon-attacker flows',len(b),'src top',b['Src IP'].value_counts().head(8).to_dict(),'dst uniq',b['Dst IP'].nunique())
print('non-attacker proto',b.Protocol.value_counts().to_dict())
print('benign dst top',b['Dst IP'].value_counts().head(8).to_dict())
# attacker flows outside windows: distribution
o=df[df.is_att&(df.run=='none')]
print('\nattacker outside-window time range',o.t.min(),o.t.max()); print(o.groupby(o.t.dt.floor('h')).size())
