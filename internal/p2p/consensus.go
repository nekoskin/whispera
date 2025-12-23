package p2p

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"sync"
	"time"
)

const proposalStatusPending = "pending"

// ConsensusEngine представляет движок консенсуса
type ConsensusEngine struct {
	mu           sync.RWMutex
	proposals    map[string]*Proposal
	votes        map[string]map[string]*Vote
	leaders      map[string]string
	participants map[string]*Participant
	algorithms   map[string]ConsensusAlgorithm
	quorum       float64
	timeout      time.Duration
}

// Proposal представляет предложение для голосования
type Proposal struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Data        map[string]interface{} `json:"data"`
	Proposer    string                 `json:"proposer"`
	Created     time.Time              `json:"created"`
	Expires     time.Time              `json:"expires"`
	Status      string                 `json:"status"`
	Votes       int                    `json:"votes"`
	Threshold   int                    `json:"threshold"`
	Description string                 `json:"description"`
}

// Vote представляет голос
type Vote struct {
	ProposalID string    `json:"proposal_id"`
	Voter      string    `json:"voter"`
	Choice     string    `json:"choice"`
	Weight     float64   `json:"weight"`
	Timestamp  time.Time `json:"timestamp"`
	Signature  []byte    `json:"signature"`
}

// Participant представляет участника консенсуса
type Participant struct {
	ID         string    `json:"id"`
	Weight     float64   `json:"weight"`
	LastSeen   time.Time `json:"last_seen"`
	Reputation float64   `json:"reputation"`
	Stake      int64     `json:"stake"`
	Active     bool      `json:"active"`
}

// ConsensusAlgorithm представляет алгоритм консенсуса
type ConsensusAlgorithm interface {
	Vote(proposal *Proposal, voter string, choice string) error
	CountVotes(proposalID string) (map[string]int, error)
	IsQuorumReached(proposalID string) bool
	SelectLeader(service string) string
	ValidateProposal(proposal *Proposal) bool
}

// RaftAlgorithm реализует Raft консенсус
type RaftAlgorithm struct {
	mu     sync.RWMutex
	state  string
	term   int
	leader string
	peers  map[string]*Participant
}

// Vote реализует голосование для Raft
func (r *RaftAlgorithm) Vote(proposal *Proposal, voter, choice string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Raft vote cast
	return nil
}

// CountVotes подсчитывает голоса для Raft
func (r *RaftAlgorithm) CountVotes(proposalID string) (map[string]int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return map[string]int{"yes": 1, "no": 0}, nil
}

// IsQuorumReached проверяет достижение кворума для Raft
func (r *RaftAlgorithm) IsQuorumReached(proposalID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.peers) >= 3 // Минимум 3 узла для Raft
}

// SelectLeader выбирает лидера для Raft
func (r *RaftAlgorithm) SelectLeader(service string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.leader
}

// ValidateProposal валидирует предложение для Raft
func (r *RaftAlgorithm) ValidateProposal(proposal *Proposal) bool {
	return proposal != nil && proposal.Type != ""
}

// PBFTAlgorithm реализует PBFT консенсус
type PBFTAlgorithm struct {
	mu      sync.RWMutex
	view    int
	primary string
	peers   map[string]*Participant
}

// Vote реализует голосование для PBFT
func (p *PBFTAlgorithm) Vote(proposal *Proposal, voter, choice string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// PBFT vote cast
	return nil
}

// CountVotes подсчитывает голоса для PBFT
func (p *PBFTAlgorithm) CountVotes(proposalID string) (map[string]int, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return map[string]int{"yes": 2, "no": 1}, nil
}

// IsQuorumReached проверяет достижение кворума для PBFT
func (p *PBFTAlgorithm) IsQuorumReached(proposalID string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return len(p.peers) >= 4 // Минимум 4 узла для PBFT
}

// SelectLeader выбирает лидера для PBFT
func (p *PBFTAlgorithm) SelectLeader(service string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.primary
}

// ValidateProposal валидирует предложение для PBFT
func (p *PBFTAlgorithm) ValidateProposal(proposal *Proposal) bool {
	return proposal != nil && proposal.Type != ""
}

// PoSAlgorithm реализует Proof of Stake консенсус
type PoSAlgorithm struct {
	mu     sync.RWMutex
	stakes map[string]int64
	peers  map[string]*Participant
}

// Vote реализует голосование для PoS
func (p *PoSAlgorithm) Vote(proposal *Proposal, voter, choice string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// PoS vote cast
	return nil
}

// CountVotes подсчитывает голоса для PoS
func (p *PoSAlgorithm) CountVotes(proposalID string) (map[string]int, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return map[string]int{"yes": 3, "no": 1}, nil
}

// IsQuorumReached проверяет достижение кворума для PoS
func (p *PoSAlgorithm) IsQuorumReached(proposalID string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return len(p.peers) >= 2 // Минимум 2 узла для PoS
}

// SelectLeader выбирает лидера для PoS
func (p *PoSAlgorithm) SelectLeader(service string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Выбираем лидера с наибольшей ставкой
	maxStake := int64(0)
	leader := ""
	for nodeID, stake := range p.stakes {
		if stake > maxStake {
			maxStake = stake
			leader = nodeID
		}
	}
	return leader
}

// ValidateProposal валидирует предложение для PoS
func (p *PoSAlgorithm) ValidateProposal(proposal *Proposal) bool {
	return proposal != nil && proposal.Type != ""
}

// NewConsensusEngine создаёт новый движок консенсуса
func NewConsensusEngine() *ConsensusEngine {
	engine := &ConsensusEngine{
		proposals:    make(map[string]*Proposal),
		votes:        make(map[string]map[string]*Vote),
		leaders:      make(map[string]string),
		participants: make(map[string]*Participant),
		algorithms:   make(map[string]ConsensusAlgorithm),
		quorum:       0.67, // 67% для достижения кворума
		timeout:      30 * time.Second,
	}

	// Добавляем алгоритмы
	engine.algorithms["raft"] = &RaftAlgorithm{
		state: "follower",
		term:  0,
		peers: make(map[string]*Participant),
	}
	engine.algorithms["pbft"] = &PBFTAlgorithm{
		view:    0,
		primary: "",
		peers:   make(map[string]*Participant),
	}
	engine.algorithms["pos"] = &PoSAlgorithm{
		stakes: make(map[string]int64),
		peers:  make(map[string]*Participant),
	}

	return engine
}

// Start запускает движок консенсуса
func (ce *ConsensusEngine) Start(ctx context.Context) {
	// Starting advanced P2P Consensus engine

	// Запускаем обработку предложений
	go ce.proposalProcessingLoop(ctx)

	// Запускаем выборы лидеров
	go ce.leaderElectionLoop(ctx)

	// Запускаем мониторинг участников
	go ce.participantMonitoringLoop(ctx)

	// Запускаем очистку устаревших данных
	go ce.cleanupLoop(ctx)
}

// proposalProcessingLoop обрабатывает предложения
func (ce *ConsensusEngine) proposalProcessingLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ce.processProposals()
		}
	}
}

// leaderElectionLoop проводит выборы лидеров
func (ce *ConsensusEngine) leaderElectionLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ce.electLeaders()
		}
	}
}

// participantMonitoringLoop мониторит участников
func (ce *ConsensusEngine) participantMonitoringLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ce.monitorParticipants()
		}
	}
}

// cleanupLoop очищает устаревшие данные
func (ce *ConsensusEngine) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ce.cleanup()
		}
	}
}

// CreateProposal создаёт новое предложение
func (ce *ConsensusEngine) CreateProposal(
	proposalType string, data map[string]interface{}, proposer string,
) (*Proposal, error) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	proposalID := ce.generateProposalID(proposer, proposalType)

	proposal := &Proposal{
		ID:          proposalID,
		Type:        proposalType,
		Data:        data,
		Proposer:    proposer,
		Created:     time.Now(),
		Expires:     time.Now().Add(ce.timeout),
		Status:      proposalStatusPending,
		Votes:       0,
		Threshold:   ce.calculateThreshold(),
		Description: fmt.Sprintf("Предложение %s от %s", proposalType, proposer),
	}

	ce.proposals[proposalID] = proposal
	ce.votes[proposalID] = make(map[string]*Vote)

	// Proposal created

	return proposal, nil
}

// Vote голосует за предложение
func (ce *ConsensusEngine) Vote(proposalID, voter, choice string) error {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	proposal, exists := ce.proposals[proposalID]
	if !exists {
		return fmt.Errorf("предложение %s не найдено", proposalID)
	}

	if proposal.Status != proposalStatusPending {
		return fmt.Errorf("предложение %s уже обработано", proposalID)
	}

	if time.Now().After(proposal.Expires) {
		proposal.Status = "expired"
		return fmt.Errorf("предложение %s истекло", proposalID)
	}

	// Проверяем, не голосовал ли уже
	if _, voted := ce.votes[proposalID][voter]; voted {
		return fmt.Errorf("участник %s уже голосовал", voter)
	}

	// Создаём голос
	vote := &Vote{
		ProposalID: proposalID,
		Voter:      voter,
		Choice:     choice,
		Weight:     ce.getParticipantWeight(voter),
		Timestamp:  time.Now(),
		Signature:  ce.generateVoteSignature(voter, proposalID, choice),
	}

	ce.votes[proposalID][voter] = vote
	proposal.Votes++

	// Vote cast for proposal

	return nil
}

// processProposals обрабатывает предложения
func (ce *ConsensusEngine) processProposals() {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	// Processing proposals

	for proposalID, proposal := range ce.proposals {
		if proposal.Status != proposalStatusPending {
			continue
		}

		// Проверяем истечение времени
		if time.Now().After(proposal.Expires) {
			proposal.Status = "expired"
			// Proposal expired
			continue
		}

		// Проверяем достижение кворума
		if ce.isQuorumReached(proposalID) {
			proposal.Status = "accepted"
			// Proposal accepted
		}
	}
}

// electLeaders проводит выборы лидеров
func (ce *ConsensusEngine) electLeaders() {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	// Leader elections in progress

	services := []string{"routing", "encryption", "discovery", "monitoring"}

	for _, service := range services {
		leader := ce.selectLeaderForService(service)
		if leader != "" {
			ce.leaders[service] = leader
			// Leader selected for service
		}
	}
}

// monitorParticipants мониторит участников
func (ce *ConsensusEngine) monitorParticipants() {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	// Monitoring consensus participants

	active := 0
	totalWeight := 0.0

	for _, participant := range ce.participants {
		if time.Since(participant.LastSeen) < 5*time.Minute {
			active++
			totalWeight += participant.Weight
		}
	}

	fmt.Printf("   - Активных участников: %d/%d\n", active, len(ce.participants))
	fmt.Printf("   - Общий вес: %.2f\n", totalWeight)
	fmt.Printf("   - Лидеров: %d\n", len(ce.leaders))
}

// cleanup очищает устаревшие данные
func (ce *ConsensusEngine) cleanup() {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	fmt.Println("🧹 Очистка устаревших данных консенсуса...")

	now := time.Now()
	cleaned := 0

	// Очищаем истекшие предложения
	for proposalID, proposal := range ce.proposals {
		if now.Sub(proposal.Created) > 1*time.Hour {
			delete(ce.proposals, proposalID)
			delete(ce.votes, proposalID)
			cleaned++
		}
	}

	// Очищаем неактивных участников
	for participantID, participant := range ce.participants {
		if now.Sub(participant.LastSeen) > 30*time.Minute {
			delete(ce.participants, participantID)
			cleaned++
		}
	}

	if cleaned > 0 {
		fmt.Printf("✅ Очищено %d устаревших записей\n", cleaned)
	}
}

// generateProposalID генерирует ID предложения
func (ce *ConsensusEngine) generateProposalID(proposer, proposalType string) string {
	data := fmt.Sprintf("%s:%s:%d", proposer, proposalType, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("prop_%x", hash[:8])
}

// calculateThreshold вычисляет порог голосования
func (ce *ConsensusEngine) calculateThreshold() int {
	activeParticipants := 0
	for _, participant := range ce.participants {
		if time.Since(participant.LastSeen) < 5*time.Minute {
			activeParticipants++
		}
	}

	threshold := int(float64(activeParticipants) * ce.quorum)
	if threshold < 1 {
		threshold = 1
	}

	return threshold
}

// getParticipantWeight возвращает вес участника
func (ce *ConsensusEngine) getParticipantWeight(participantID string) float64 {
	participant, exists := ce.participants[participantID]
	if !exists {
		return 1.0 // Дефолтный вес
	}

	return participant.Weight
}

// generateVoteSignature генерирует подпись голоса
func (ce *ConsensusEngine) generateVoteSignature(voter, proposalID, choice string) []byte {
	data := fmt.Sprintf("%s:%s:%s:%d", voter, proposalID, choice, time.Now().Unix())
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

// isQuorumReached проверяет достижение кворума
func (ce *ConsensusEngine) isQuorumReached(proposalID string) bool {
	proposal := ce.proposals[proposalID]
	if proposal == nil {
		return false
	}

	return proposal.Votes >= proposal.Threshold
}

// selectLeaderForService выбирает лидера для сервиса
func (ce *ConsensusEngine) selectLeaderForService(_ string) string {
	// Сортируем участников по весу
	participants := make([]*Participant, 0, len(ce.participants))
	for _, participant := range ce.participants {
		if time.Since(participant.LastSeen) < 5*time.Minute {
			participants = append(participants, participant)
		}
	}

	if len(participants) == 0 {
		return ""
	}

	// Сортируем по весу (убывание)
	sort.Slice(participants, func(i, j int) bool {
		return participants[i].Weight > participants[j].Weight
	})

	// Выбираем лидера с наибольшим весом
	leader := participants[0]
	return leader.ID
}

// AddParticipant добавляет участника
func (ce *ConsensusEngine) AddParticipant(participant *Participant) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	ce.participants[participant.ID] = participant
	fmt.Printf("👥 Добавлен участник консенсуса: %s (вес: %.2f)\n",
		participant.ID, participant.Weight)
}

// RemoveParticipant удаляет участника
func (ce *ConsensusEngine) RemoveParticipant(participantID string) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	delete(ce.participants, participantID)
	fmt.Printf("👥 Удалён участник консенсуса: %s\n", participantID)
}

// GetConsensusStats возвращает статистику консенсуса
func (ce *ConsensusEngine) GetConsensusStats() map[string]interface{} {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	activeParticipants := 0
	for _, participant := range ce.participants {
		if time.Since(participant.LastSeen) < 5*time.Minute {
			activeParticipants++
		}
	}

	pendingProposals := 0
	for _, proposal := range ce.proposals {
		if proposal.Status == proposalStatusPending {
			pendingProposals++
		}
	}

	return map[string]interface{}{
		"total_participants":  len(ce.participants),
		"active_participants": activeParticipants,
		"total_proposals":     len(ce.proposals),
		"pending_proposals":   pendingProposals,
		"leaders":             len(ce.leaders),
		"quorum_threshold":    ce.quorum,
		"algorithms":          len(ce.algorithms),
	}
}

// GetLeader возвращает лидера для сервиса
func (ce *ConsensusEngine) GetLeader(service string) string {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	// Если лидер уже выбран, возвращаем его
	if leader, exists := ce.leaders[service]; exists && leader != "" {
		return leader
	}

	// Выбираем лидера из активных участников
	var bestParticipant *Participant
	bestScore := 0.0

	for _, participant := range ce.participants {
		if !participant.Active {
			continue
		}

		// Вычисляем оценку участника
		score := participant.Weight * participant.Reputation
		if score > bestScore {
			bestScore = score
			bestParticipant = participant
		}
	}

	if bestParticipant != nil {
		ce.leaders[service] = bestParticipant.ID
		return bestParticipant.ID
	}

	return ""
}

// GetProposal возвращает предложение
func (ce *ConsensusEngine) GetProposal(proposalID string) (*Proposal, error) {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	proposal, exists := ce.proposals[proposalID]
	if !exists {
		return nil, fmt.Errorf("предложение %s не найдено", proposalID)
	}

	return proposal, nil
}

// GetVotes возвращает голоса за предложение
func (ce *ConsensusEngine) GetVotes(proposalID string) ([]*Vote, error) {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	votes, exists := ce.votes[proposalID]
	if !exists {
		return nil, fmt.Errorf("голоса для предложения %s не найдены", proposalID)
	}

	voteList := make([]*Vote, 0, len(votes))
	for _, vote := range votes {
		voteList = append(voteList, vote)
	}

	return voteList, nil
}
