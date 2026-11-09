import pandas as pd, numpy as np
pd.set_option('display.width',250); pd.set_option('display.max_columns',40); pd.set_option('display.max_rows',200)
log=pd.read_csv('dataset/Attack_log-20261109T113913Z-1-001/Attack_log/attack_log.csv')
B='dataset/csv/sesi%d_all.csv/sesi%d_all.csv'
mn={};mx={};nanc={}
for s_ in (1,2,3):
    for ch in pd.read_csv(B%(s_,s_),chunksize=500000,low_memory=False):
        n=ch.select_dtypes(include=[np.number]).replace([np.inf,-np.inf],np.nan)
        for c in n.columns:
            mn[c]=min(mn.get(c,np.inf),n[c].min()); mx[c]=max(mx.get(c,-np.inf),n[c].max()); nanc[c]=nanc.get(c,0)+int(n[c].isna().sum())
const=[c for c in mn if mn[c]==mx[c]]
print('constant cols',len(const),const)
print('NaN cols',{k:v for k,v in nanc.items() if v})
U=['Src IP','Dst IP','Protocol','Timestamp','Total Fwd Packet','Total Length of Fwd Packet']
df=pd.concat([pd.read_csv(B%(s_,s_),usecols=U) for s_ in (1,2,3)],ignore_index=True)
df['t']=pd.to_datetime(df['Timestamp'],format='%d/%m/%Y %I:%M:%S %p')
df['ep']=(df['t']-pd.Timestamp('1970-01-01')).dt.total_seconds().astype('int64')
# tumbling 60s windows, label by log (full containment only)
df['w']=df['ep']//60*60
df['bytes']=df['Total Length of Fwd Packet']; df['pk']=df['Total Fwd Packet']
def ent(x):
    p=x/x.sum(); p=p[p>0]; return float(-(p*np.log2(p)).sum())
rows=[]
for w,g in df.groupby('w'):
    t=g.groupby('Dst IP')['pk'].sum()
    rows.append(dict(w=w,flows=len(g),uDst=len(t),ent=ent(t.values),pk=int(t.sum()),by=int(g.bytes.sum()),conc=t.max()/t.sum(),uSrc=g['Src IP'].nunique(),udp=(g.Protocol==17).mean()))
W=pd.DataFrame(rows)
W['label']='benign'; W['run']='-'
amb=np.zeros(len(W),bool)
for _,r in log.iterrows():
    inside=(W.w>=r.start_ts)&(W.w+60<=r.end_ts)
    overlap=(W.w+60>r.start_ts)&(W.w<=r.end_ts)
    W.loc[inside,'run']=r.run_id; W.loc[inside,'label']='carpet' if r.scenario.startswith('carpet') else 'focused'
    amb|=(overlap&~inside).values
W['boundary']=amb
print('windows total',len(W),'boundary(partial overlap)',int(amb.sum()))
print(W.groupby('label').size().to_dict(), ' (excluding boundary):',W[~W.boundary].groupby('label').size().to_dict())
c=W[~W.boundary]
print(c.groupby('label')[['flows','uDst','ent','pk','by','conc','uSrc','udp']].agg(['min','median','max']).T.to_string())
# unlogged attack windows labeled benign
att=df[df['Src IP']=='192.168.1.65'].groupby('w').size()
bad=W[(W.label=='benign')&W.w.isin(att[att>1000].index)]
print('benign-labeled windows with >1000 attacker flows (unlogged attack):',len(bad),bad.w.map(lambda x:pd.Timestamp(x,unit='s')).tolist())
# trivially separable features?
for f in ['pk','uDst','ent','conc','uSrc','flows','by']:
    for pos in ('carpet','focused'):
        a=c[c.label==pos][f]; b=c[c.label=='benign'][f]
        print(f,pos,'overlap with benign range:', 'YES' if a.min()<=b.max() and b.min()<=a.max() else 'no', '| carpet/focused min',a.min(),'benign max',b.max())
# carpet vs focused separation on dst-distribution features
cf=c[c.label!='benign']
print(cf.groupby('label')[['uDst','ent','conc']].describe().T.to_string())
