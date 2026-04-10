import type { Note } from '../types';

interface Props {
  notes: Note[];
}

export default function NoteList({ notes }: Props) {
  if (notes.length === 0) {
    return (
      <div className="panel">
        <h2>Notes</h2>
        <p className="panel-desc">
          Your shielded notes will appear here once you shield Runes or receive
          a private transfer.
        </p>
        <div className="empty-state">No notes yet</div>
      </div>
    );
  }

  return (
    <div className="panel">
      <h2>Notes</h2>
      <p className="panel-desc">
        These are your private note commitments stored on-chain.
      </p>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Rune ID</th>
              <th>Amount</th>
              <th>Commitment</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {notes.map((note, i) => (
              <tr key={i} className={note.spent ? 'row-spent' : ''}>
                <td>{note.note_index}</td>
                <td>{note.rune_id}</td>
                <td>{note.amount}</td>
                <td className="mono" title={note.commitment}>
                  {note.commitment.slice(0, 10)}...{note.commitment.slice(-6)}
                </td>
                <td>
                  <span className={`badge ${note.spent ? 'badge-spent' : 'badge-unspent'}`}>
                    {note.spent ? 'Spent' : 'Unspent'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
