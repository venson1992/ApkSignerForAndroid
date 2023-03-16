package com.venson.apk.signer

import android.view.LayoutInflater
import android.view.ViewGroup
import android.widget.CheckedTextView
import androidx.recyclerview.widget.RecyclerView
import androidx.recyclerview.widget.RecyclerView.ViewHolder

class KeyListAdapter(private val mKeyDataList: MutableList<SignActivity.KeyData>) :
    RecyclerView.Adapter<ViewHolder>() {

    private var mCurrentPosition = 0

    private var mOnItemClickListener: ((position: Int) -> Unit)? = null

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val itemView = LayoutInflater.from(parent.context)
            .inflate(android.R.layout.simple_list_item_checked, parent, false)
        return object : ViewHolder(itemView) {

        }
    }

    override fun getItemCount(): Int {
        return mKeyDataList?.size ?: 0
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        holder.itemView.findViewById<CheckedTextView>(android.R.id.text1)?.let { textView ->
            textView.isChecked = position == mCurrentPosition
            textView.text = mKeyDataList?.get(position)?.fileName ?: ""
            textView.setOnClickListener {
                mOnItemClickListener?.invoke(position)
                val oldPosition = mCurrentPosition
                mCurrentPosition = position
                try {
                    notifyItemChanged(oldPosition)
                } catch (ignore: Exception) {

                }
                try {
                    notifyItemChanged(mCurrentPosition)
                } catch (ignore: Exception) {

                }
            }
        }
    }

    fun setOnItemClickListener(listener: (position: Int) -> Unit) {
        mOnItemClickListener = listener
    }

}