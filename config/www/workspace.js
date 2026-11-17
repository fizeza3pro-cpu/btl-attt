const roles = {customer:'Khách hàng',staff:'Nhân viên',admin:'Quản trị viên'};
const dateLabel = s => new Date(s.includes('T') ? s : s.replace(' ','T')+'Z').toLocaleString('vi-VN');
function orderTable(rows, personal) {
  if (!rows.length) return '<p class="empty-state">Chưa có đơn hàng. <a href="/index.html">Khám phá sản phẩm</a></p>';
  return `<table><thead><tr><th>Mã đơn</th>${personal?'':'<th>Khách hàng</th>'}<th>Thời gian</th><th>Số lượng</th><th>Tổng tiền</th></tr></thead><tbody>${rows.map(r=>`<tr><td>${personal?`<button class="order-link" data-order="${Number(r.id)}">${escShop(r.order_code)}</button>`:escShop(r.order_code)}</td>${personal?'':`<td>${escShop(r.email)}</td>`}<td>${escShop(dateLabel(r.created_at))}</td><td>${Number(r.count)}</td><td><b>${fmt(r.total)}</b></td></tr>`).join('')}</tbody></table>`;
}
document.addEventListener('DOMContentLoaded',async()=>{
  const identity=document.getElementById('identity');
  if(!identity) return;
  const staff=location.pathname.startsWith('/staff/');
  try {
    const me=await api('/api/me');
    if(!me.logged_in){identity.innerHTML='<h2>Bạn chưa đăng nhập</h2><p>Đăng nhập để xem thông tin và đơn hàng.</p><a class="btn" href="/login.html?next=account.html">Đăng nhập</a>';document.getElementById('orders').textContent='Đơn hàng sẽ xuất hiện sau khi đăng nhập.';return;}
    identity.innerHTML=`<div class="identity"><span class="initial">${escShop(me.name.slice(0,1))}</span><div><h2>${escShop(me.name)}</h2><p>${escShop(me.email)} <span class="role-badge">${escShop(roles[me.role]||me.role)}</span></p></div>${!staff&&['staff','admin'].includes(me.role)?'<a class="btn" href="/staff/">Vào khu vận hành</a>':''}</div>`;
    if(staff&&!['staff','admin'].includes(me.role)){identity.innerHTML+='<p class="err">Tài khoản này không có quyền vận hành cửa hàng.</p>';return;}
    const orders=await api(staff?'/api/staff/orders':'/api/orders');
    if(staff) document.getElementById('staff-orders-panel').hidden=false;
    document.getElementById('order-count').textContent=orders.orders.length+' đơn hàng';
    document.getElementById('orders').innerHTML=orderTable(orders.orders,!staff);
    if(staff&&me.role==='admin') {
      const users=await api('/api/staff/users');document.getElementById('users-panel').hidden=false;
      const active=users.users.filter(u=>u.is_active).length,revenue=orders.orders.reduce((sum,o)=>sum+Number(o.total||0),0),summary=document.getElementById('staff-summary');
      summary.hidden=false;summary.innerHTML=`<article><span>Đơn hàng</span><strong>${orders.orders.length}</strong></article><article><span>Doanh thu ghi nhận</span><strong>${fmt(revenue)}</strong></article><article><span>Tài khoản hoạt động</span><strong>${active}/${users.users.length}</strong></article>`;
      document.getElementById('users').innerHTML=`<table><thead><tr><th>ID</th><th>Họ tên</th><th>Email</th><th>Vai trò</th><th>Trạng thái</th><th>Thao tác</th></tr></thead><tbody>${users.users.map(u=>`<tr><td>${Number(u.id)}</td><td>${escShop(u.name)}</td><td>${escShop(u.email)}</td><td><span class="role-badge">${escShop(roles[u.role]||u.role)}</span></td><td><span class="account-status ${u.is_active?'active':'locked'}">${u.is_active?'Đang hoạt động':'Đã khóa'}</span></td><td>${u.email===me.email?'<span class="muted-copy">Phiên hiện tại</span>':`<button class="account-action" data-user-status="${Number(u.id)}" data-active="${u.is_active?'0':'1'}">${u.is_active?'Khóa':'Mở khóa'}</button>`}</td></tr>`).join('')}</tbody></table>`;
    }
    const logout=document.getElementById('logout');if(logout){logout.hidden=false;logout.onclick=async()=>{try{await api('/api/logout',{method:'POST',body:'{}'});location.reload();}catch(e){toast(e.message,true);}};}
  }catch(e){identity.textContent='Không tải được dữ liệu: '+e.message;}
});
document.addEventListener('click',async e=>{
  const status=e.target.closest('[data-user-status]');
  if(status){const active=status.dataset.active==='1';if(!confirm(`${active?'Mở khóa':'Khóa'} tài khoản này?`))return;status.disabled=true;try{await api(`/api/staff/users/${status.dataset.userStatus}/status`,{method:'POST',body:JSON.stringify({active})});toast(active?'Đã mở khóa tài khoản':'Đã khóa tài khoản');location.reload();}catch(error){toast(error.message,true);status.disabled=false;}return;}
  const button=e.target.closest('[data-order]');if(!button)return;
  const box=document.getElementById('order-detail');box.hidden=false;box.textContent='Đang tải chi tiết…';
  try{const d=await api('/api/orders/'+button.dataset.order);box.innerHTML=`<h2>Đơn ${escShop(d.order.order_code)}</h2><table><thead><tr><th>Sản phẩm</th><th>Số lượng</th><th>Đơn giá</th></tr></thead><tbody>${d.items.map(i=>`<tr><td>${escShop(i.name)}</td><td>${Number(i.qty)}</td><td>${fmt(i.price)}</td></tr>`).join('')}</tbody></table>`;box.scrollIntoView({block:'nearest'});}catch(error){box.textContent=error.message;}
});
